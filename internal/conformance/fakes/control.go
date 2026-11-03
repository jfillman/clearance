// Package fakes holds reference providers for the conformance harness: a runtime provider (the gateway's shape)
// and a deployment provider (a deployment gate's shape) that follow docs/provider-protocol.md, and broken variants
// that each break one rule (Runtime.ActOnDeny, Deployment.ApplyBeforeClear). They are test fixtures and protocol
// examples, not providers: they serve only the conformance control interface, which a real provider keeps off by
// default.
package fakes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/conformance"
)

// flowTimeout bounds one apply's whole flow (a deployment provider polling a held change).
const flowTimeout = 2 * time.Minute

// control is the conformance control interface over a role's flow: it takes an apply, runs flow in the background,
// and serves the status flow reports.
type control struct {
	info   conformance.Info
	role   string
	flow   func(ctx context.Context, a conformance.ApplyRequest, set func(func(*conformance.Status)))
	client *http.Client

	mu      sync.Mutex
	applies map[string]*conformance.Status
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func newControl(info conformance.Info, role string) *control {
	ctx, cancel := context.WithCancel(context.Background())
	return &control{info: info, role: role, applies: map[string]*conformance.Status{}, ctx: ctx, cancel: cancel,
		client: &http.Client{Timeout: 10 * time.Second}}
}

func (c *control) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+conformance.PathInfo, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, c.info)
	})
	mux.HandleFunc("POST "+conformance.PathApply, c.apply)
	mux.HandleFunc("GET "+conformance.PathApplies+"{id}", c.status)
	return mux
}

// Close stops every flow in flight and waits for them.
func (c *control) Close() {
	c.cancel()
	c.wg.Wait()
}

func (c *control) apply(w http.ResponseWriter, r *http.Request) {
	a, err := conformance.DecodeApply(r.Body)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, conformance.ErrTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if a.Role != c.role {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this provider is a " + c.role + " provider"})
		return
	}
	c.mu.Lock()
	if _, dup := c.applies[a.ID]; dup {
		c.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "apply " + a.ID + " already exists"})
		return
	}
	c.applies[a.ID] = &conformance.Status{ID: a.ID, State: conformance.StateAccepted}
	c.mu.Unlock()
	set := func(edit func(*conformance.Status)) {
		c.mu.Lock()
		edit(c.applies[a.ID])
		c.mu.Unlock()
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ctx, cancel := context.WithTimeout(c.ctx, flowTimeout)
		defer cancel()
		c.flow(ctx, a, set)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"id": a.ID})
}

func (c *control) status(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	st, ok := c.applies[r.PathValue("id")]
	var out conformance.Status
	if ok {
		out = *st
	}
	c.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such apply"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// errUnavailable is a core that did not answer, or answered 5xx: the provider's outage policy applies.
var errUnavailable = errors.New("the core is unavailable")

// post sends body to url with bearer and decodes a 2xx answer into out. A transport error or a 5xx is
// errUnavailable (wrapped); any other non-2xx is an error carrying the status.
func (c *control) post(ctx context.Context, url, bearer string, body any, out any) (int, error) {
	raw, ok := body.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errUnavailable, err)
	}
	defer resp.Body.Close()
	ans, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%w: %v", errUnavailable, err)
	}
	if resp.StatusCode >= 500 {
		return resp.StatusCode, fmt.Errorf("%w: status %d", errUnavailable, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("status %d: %s", resp.StatusCode, bytes.TrimSpace(ans))
	}
	if out != nil {
		if err := json.Unmarshal(ans, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// applyTarget acts on the target: POST /v1/apply with the content.
func (c *control) applyTarget(ctx context.Context, a conformance.ApplyRequest, content string) (conformance.TargetReceipt, error) {
	var rc conformance.TargetReceipt
	_, err := c.post(ctx, a.Target.URL+conformance.PathTargetApply, a.Target.Bearer,
		conformance.TargetApply{ID: a.ID, Content: content}, &rc)
	return rc, err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
