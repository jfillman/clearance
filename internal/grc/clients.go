package grc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Reader reads the gate's changes from clearance-api as this service's own principal (the notifier role): its
// projected service-account token, read from the file on every call and never held.
type Reader struct {
	API       string
	TokenFile string
	HTTP      *http.Client
}

func bearer(file string) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", errors.New("cannot read the service-account token file")
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("the service-account token file is empty")
	}
	return t, nil
}

// maxPage caps a list answer; a page is at most 200 changes.
const maxPage = 32 << 20

// Changes lists the changes in state (and env) decided since, newest first, up to max.
func (r *Reader) Changes(ctx context.Context, state, env string, since time.Time, max int) ([]gate.Change, error) {
	var out []gate.Change
	q := url.Values{"state": {state}, "limit": {"200"}, "since": {since.UTC().Format("2006-01-02T15:04:05Z")}}
	if env != "" {
		q.Set("env", env)
	}
	for len(out) < max {
		tok, err := bearer(r.TokenFile)
		if err != nil {
			return out, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.API+"/v1/clearances?"+q.Encode(), nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "clearance-grc")
		resp, err := r.HTTP.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return out, fmt.Errorf("cannot reach clearance-api: %w", err)
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxPage))
		resp.Body.Close()
		if rerr != nil {
			return out, rerr
		}
		if resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("clearance-api answered HTTP %d", resp.StatusCode)
		}
		var page struct {
			Items []json.RawMessage `json:"items"`
			Next  *string           `json:"next"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return out, errors.New("clearance-api answered something that is not a change page")
		}
		for _, it := range page.Items {
			if c, err := gate.FromRecord(it); err == nil {
				out = append(out, *c)
			}
		}
		if page.Next == nil || len(page.Items) == 0 {
			break
		}
		q.Set("after", *page.Next)
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// Ledger writes the push's records to the core (POST /v1/records) as the registered provider.
type Ledger struct {
	Core      string
	TokenFile string
	Provider  string
	HTTP      *http.Client
}

// Record is a grc.push or grc.report record's claimed fields.
type Record struct {
	Kind   string
	Target string // the hub
	Result string // pushed or failed
	// Change is the change id (grc.push of one change); empty for a report or a failed batch.
	Change string
	// Digest is the SHA-256 of what was sent (the item, or the set a failed push was carrying).
	Digest string
	// EventID makes the record idempotent at the core: the same hub and event id is recorded once.
	EventID string
	// Reason is a failure class (never a hub's text).
	Reason string
	Link   string
	Count  int
}

// Write records r. It returns whether the core already held it (a repeat).
func (l *Ledger) Write(ctx context.Context, r Record) (duplicate bool, err error) {
	tok, err := bearer(l.TokenFile)
	if err != nil {
		return false, err
	}
	rec := map[string]any{"target": r.Target, "result": r.Result}
	if r.Digest != "" {
		rec["args_sha256"] = r.Digest
	}
	if r.Reason != "" {
		rec["reason"] = r.Reason
	}
	if r.Change != "" {
		rec["change"] = map[string]any{"id": r.Change}
	}
	if r.EventID != "" {
		rec["source"] = map[string]any{"name": r.Target, "event_id": r.EventID}
	}
	dest := map[string]any{"hub": r.Target}
	if r.Link != "" {
		dest["link"] = r.Link
	}
	if r.Count > 0 {
		dest["items"] = r.Count
	}
	rec["destination"] = dest
	body, _ := json.Marshal(map[string]any{"provider": l.Provider, "kind": r.Kind, "record": rec})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.Core+"/v1/records", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clearance-grc")
	resp, err := l.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return false, fmt.Errorf("cannot reach the core: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("the core answered HTTP %d recording a %s", resp.StatusCode, r.Kind)
	}
	var ans struct {
		Duplicate bool `json:"duplicate"`
	}
	_ = json.Unmarshal(raw, &ans)
	return ans.Duplicate, nil
}
