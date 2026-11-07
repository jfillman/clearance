package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// The signed grant feed (C-10, token.Feed): per cluster, every clearance token live there, signed by the token key.
// The core signs a cluster's feed in the same transaction as any write to one of its tokens (issue, re-issue,
// revoke), so the stored feed always matches the stored tokens, and re-signs every cluster's feed at least every
// FeedResign (RefreshFeeds, from the core's minute loop), so a feed older than FeedTTL means the core or the path to
// it is down. clearance-api serves the stored row as it is (GET /v1/grant-feeds/{cluster}): it holds no key.
const (
	FeedTTL    = 5 * time.Minute
	FeedResign = 2 * time.Minute
)

// ErrFeedTooLarge is a cluster with more live tokens than a feed lists (token.MaxFeedEntries). Its feed is not
// re-signed, so it goes stale and the cluster's grant-sync stops updating grants (fail closed); RefreshFeeds
// reports it.
var ErrFeedTooLarge = errors.New("gate: more live tokens on the cluster than a grant feed lists")

// FeedToken is one token as served beside the feed: its change id and the token (a TokenView).
type FeedToken struct {
	ChangeID string `json:"change_id"`
	TokenView
}

// touch notes that the operation wrote change id (on cluster): its watchers are woken and its cluster's feed is
// re-signed when the operation commits.
func (w *writer) touch(id, cluster string) {
	if w.touched == nil {
		w.touched = map[string]string{}
	}
	w.touched[id] = cluster
}

// signFeeds re-signs the feed of every cluster the operation touched, inside its transaction.
func (w *writer) signFeeds() {
	if w.err != nil || w.svc == nil || w.svc.Tokens == nil {
		return
	}
	done := map[string]bool{}
	for _, cluster := range w.touched {
		if cluster == "" || done[cluster] {
			continue
		}
		done[cluster] = true
		if err := w.svc.signFeed(w.ctx, w.tx, cluster, w.now); err != nil && !errors.Is(err, ErrFeedTooLarge) {
			w.err = err
			return
		}
	}
}

// signFeed signs cluster's feed at now from the live tokens tx sees, and stores it.
func (s *Service) signFeed(ctx context.Context, tx store.Tx, cluster string, now time.Time) error {
	live, err := tx.LiveTokens(ctx, cluster, now, token.MaxFeedEntries+1)
	if err != nil {
		return err
	}
	if len(live) > token.MaxFeedEntries {
		return fmt.Errorf("%w: %s", ErrFeedTooLarge, cluster)
	}
	var seq int64 = 1
	prev, err := tx.Feed(ctx, cluster)
	switch {
	case err == nil:
		seq = prev.Seq + 1
	case !errors.Is(err, store.ErrNotFound):
		return err
	}
	head, _, err := tx.Head(ctx)
	if err != nil {
		return err
	}
	epoch, err := feedEpoch(ctx, tx)
	if err != nil {
		return err
	}
	f := token.Feed{Type: token.FeedType, Issuer: s.Tokens.issuer(), Cluster: cluster, Epoch: epoch, Seq: seq,
		IssuedAt: now.Unix(), Expires: now.Add(FeedTTL).Unix(), RecordsSeq: head, Entries: []token.FeedEntry{}}
	served := make([]FeedToken, 0, len(live))
	for _, tk := range live {
		v, err := ViewToken(tk)
		if err != nil {
			return err
		}
		d, err := token.PayloadDigest(v.DSSE)
		if err != nil {
			return fmt.Errorf("gate: stored token %s: %w", tk.ChangeID, err)
		}
		f.Entries = append(f.Entries, token.FeedEntry{ChangeID: tk.ChangeID, Nonce: tk.Nonce,
			Expires: tk.ExpiresAt.Unix(), PayloadSHA256: d})
		served = append(served, FeedToken{ChangeID: tk.ChangeID, TokenView: *v})
	}
	env, err := token.SignFeed(ctx, s.Tokens.Signer, f)
	if err != nil {
		return fmt.Errorf("gate: signing the grant feed: %w", err)
	}
	rawEnv, err := json.Marshal(env)
	if err != nil {
		return err
	}
	rawToks, err := json.Marshal(served)
	if err != nil {
		return err
	}
	return tx.PutFeed(ctx, store.Feed{Cluster: cluster, Seq: seq, KeyID: s.Tokens.Signer.KeyID(),
		IssuedAt: time.Unix(f.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(f.Expires, 0).UTC(), Envelope: rawEnv, Tokens: rawToks})
}

// feedEpoch names the database a feed's seq counts in: the hash of the chain's first record, which no two databases
// share (it carries the time it was written) and which a rebuilt or restored database does not keep. An empty chain
// has the genesis hash (it signs no feed until a token exists, and a token comes with a record).
func feedEpoch(ctx context.Context, tx store.Tx) (string, error) {
	first, err := tx.Records(ctx, 0, 1)
	if err != nil {
		return "", err
	}
	if len(first) == 0 {
		return store.Genesis, nil
	}
	h, _ := first[0]["hash"].(string)
	if h == "" {
		return "", errors.New("gate: the chain's first record has no hash")
	}
	return h, nil
}

// RefreshFeeds re-signs every cluster's feed that is older than FeedResign or signed by a key the core no longer
// uses (a restart with a new key), and returns how many it signed. A cluster too large to list is skipped and
// reported in the error; the others are still signed.
func (s *Service) RefreshFeeds(ctx context.Context) (int, error) {
	if s.Tokens == nil || s.Config.Off {
		return 0, nil
	}
	var signed int
	var tooLarge error
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		clusters, err := tx.FeedClusters(ctx)
		if err != nil {
			w.err = err
			return err
		}
		for _, c := range clusters {
			prev, err := tx.Feed(ctx, c)
			if err == nil && w.now.Sub(prev.IssuedAt) < FeedResign && prev.KeyID == s.Tokens.Signer.KeyID() {
				continue
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				w.err = err
				return err
			}
			if err := s.signFeed(ctx, tx, c, w.now); errors.Is(err, ErrFeedTooLarge) {
				tooLarge = errors.Join(tooLarge, err)
				continue
			} else if err != nil {
				w.err = err
				return err
			}
			signed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return signed, tooLarge
}
