package traefikhub

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/jfillman/clearance/client"
)

// Key is the record's identity for de-duplication: the SHA-256 of its decision line. The same Hub line read twice
// (a re-run over a log that grew) has the same key; the ledger is append-only, so a re-run must not post it again.
func Key(r *client.RecordRequest) string {
	if d, ok := r.Record.Subject["digests"].(map[string]any); ok {
		if k, ok := d["decisionLine"].(string); ok {
			return k
		}
	}
	return ""
}

// State is the set of keys already posted, kept in a file of one key per line (appended as each record lands).
type State struct {
	seen map[string]bool
	w    io.Writer
}

var keyLine = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MaxStateKeys caps a state file.
const MaxStateKeys = 10_000_000

// OpenState reads path (missing is empty) and appends to it. Close the returned closer when done.
func OpenState(path string) (*State, io.Closer, error) {
	st := &State{seen: map[string]bool{}}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k := sc.Text()
			if !keyLine.MatchString(k) {
				f.Close()
				return nil, nil, fmt.Errorf("traefikhub: state %s: a line that is not a key", path)
			}
			if len(st.seen) >= MaxStateKeys {
				f.Close()
				return nil, nil, fmt.Errorf("traefikhub: state %s: more than %d keys", path, MaxStateKeys)
			}
			st.seen[k] = true
		}
		err := sc.Err()
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("traefikhub: state %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("traefikhub: state: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("traefikhub: state: %w", err)
	}
	st.w = f
	return st, f, nil
}

// Seen reports whether key was posted.
func (s *State) Seen(key string) bool { return s != nil && s.seen[key] }

func (s *State) mark(key string) error {
	if s == nil {
		return nil
	}
	s.seen[key] = true
	if s.w == nil {
		return nil
	}
	_, err := io.WriteString(s.w, key+"\n")
	return err
}

// PostStats counts a Post.
type PostStats struct {
	Posted  int `json:"posted"`
	Skipped int `json:"skipped"` // already in the state
}

// Post sends each record in order through POST /v1/records, skipping those the state has, and stops at the first
// failure (the records after it are posted by the next run). state may be nil (no de-duplication).
//
// Delivery is at least once: a key is marked after the core answers. If the core recorded a record and its answer
// was lost, the next run posts it again. Marking first would make delivery at most once and lose that record for
// good when the post never landed; in an evidence ledger a missing decision is worse than a repeated one, and a
// repeat is recognisable (the same subject.digests.decisionLine). The core does not de-duplicate POST /v1/records.
func Post(ctx context.Context, c *client.Client, recs []client.RecordRequest, state *State) error {
	_, err := PostCounted(ctx, c, recs, state)
	return err
}

// PostCounted is Post with its counts.
func PostCounted(ctx context.Context, c *client.Client, recs []client.RecordRequest, state *State) (PostStats, error) {
	var ps PostStats
	for i := range recs {
		k := Key(&recs[i])
		if k != "" && state.Seen(k) {
			ps.Skipped++
			continue
		}
		if _, err := c.Record(ctx, &recs[i]); err != nil {
			return ps, fmt.Errorf("traefikhub: record %d: %w", i, err)
		}
		ps.Posted++
		if k != "" {
			if err := state.mark(k); err != nil {
				return ps, fmt.Errorf("traefikhub: state: %w", err)
			}
		}
	}
	return ps, nil
}
