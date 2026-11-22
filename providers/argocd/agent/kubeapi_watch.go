package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// The active grants of every namespace, listed and watched: what the grant-expiry webhook (providers/argocd/grantexpiry)
// keeps in its cache. The selector is the admission policy's paramRef selector, clearance.hangar.io/active=true, and
// nothing else (not the agent's managed-by label): the webhook reads the grants the policy reads.

// GrantEvent is one event of a grant watch. Type is ADDED, MODIFIED, DELETED (a grant deleted, or one that lost the
// active label and so left the selection) or BOOKMARK (no grant; only RV moves).
type GrantEvent struct {
	Type  string
	Grant Grant
	RV    string
}

func (a *API) activeGrantsPath() string {
	return a.grantPath("", "") + "?labelSelector=" + url.QueryEscape(LabelActive+"=true")
}

// activeGrantsPage is how many grants one list page asks for: a merged grant can be 1.5 MB, so a page stays far below
// the 64 MiB a single read is capped at however many protected namespaces there are.
var activeGrantsPage = 20

// ListActiveGrants lists the grants labelled clearance.hangar.io/active=true in every namespace, in pages (limit and
// continue), with the list's resourceVersion (the last page's) to watch from.
func (a *API) ListActiveGrants(ctx context.Context) ([]Grant, string, error) {
	var out []Grant
	cont := ""
	for {
		var l struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue"`
			} `json:"metadata"`
			Items []grantWire `json:"items"`
		}
		q := a.activeGrantsPath() + "&limit=" + strconv.Itoa(activeGrantsPage)
		if cont != "" {
			q += "&continue=" + url.QueryEscape(cont)
		}
		if err := a.call(ctx, "GET", q, "", nil, &l); err != nil {
			return nil, "", err // a 410 (the continue token expired) fails the whole list: the caller lists again
		}
		for _, w := range l.Items {
			out = append(out, w.grant())
		}
		if l.Metadata.Continue == "" {
			return out, l.Metadata.ResourceVersion, nil
		}
		cont = l.Metadata.Continue
	}
}

// WatchActiveGrants watches the same selection from rv and calls fn per event until ctx ends, the server ends the
// watch (nil) or the stream breaks (the error; ErrWatchGone: rv is too old, list again).
func (a *API) WatchActiveGrants(ctx context.Context, rv string, fn func(GrantEvent)) error {
	q := "&watch=true&allowWatchBookmarks=true&timeoutSeconds=300&resourceVersion=" + url.QueryEscape(rv)
	resp, err := a.do(ctx, "GET", a.activeGrantsPath()+q, "", nil, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrWatchGone
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return &StatusError{resp.StatusCode, truncate(string(b), 300)}
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return err
		}
		if ev.Type == "ERROR" {
			var st struct {
				Code int `json:"code"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return ErrWatchGone
			}
			return fmt.Errorf("agent: watch error %s", truncate(string(ev.Object), 200))
		}
		var w grantWire
		var m struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(ev.Object, &w); err != nil {
			return err
		}
		_ = json.Unmarshal(ev.Object, &m)
		switch ev.Type {
		case "ADDED", "MODIFIED", "DELETED":
			fn(GrantEvent{Type: ev.Type, Grant: w.grant(), RV: m.Metadata.ResourceVersion})
		case "BOOKMARK":
			fn(GrantEvent{Type: ev.Type, RV: m.Metadata.ResourceVersion})
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
