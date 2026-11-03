// Command installtest is the chart's install test (.github/workflows/chart.yaml): run in the cluster as a fake
// provider, it proves an installed Clearance decides, records and clears. One PASS or FAIL line per check; exit 1 on
// any FAIL.
//
//	installtest --core http://clearance-core.clearance:8080 [--api http://clearance-api.clearance:8080]
//	            [--token-file /var/run/clearance/token]
//
// The token is the pod's projected service-account token for the core's audience: the core authenticates it by
// TokenReview, and the pod's service account is registered in CLEARANCE_PROVIDERS and CLEARANCE_VERIFIERS by the
// test values. With --api it also reads the decision back from clearance-api and checks the chain there.
//
// It needs nothing from Airframe, Glidepath or Autopilot: the evaluation and the change are fixed fakes.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	core := flag.String("core", os.Getenv("INSTALLTEST_CORE_URL"), "the core's URL")
	api := flag.String("api", os.Getenv("INSTALLTEST_API_URL"), "clearance-api's URL (optional)")
	tokenFile := flag.String("token-file", "/var/run/clearance/token", "the projected token for the core's audience")
	wait := flag.Duration("wait", 2*time.Minute, "how long to wait for /readyz")
	flag.Parse()
	if *core == "" {
		fmt.Fprintln(os.Stderr, "installtest: --core is required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait+2*time.Minute)
	defer cancel()
	t := &tester{core: strings.TrimRight(*core, "/"), api: strings.TrimRight(*api, "/"), tokenFile: *tokenFile,
		http: &http.Client{Timeout: 15 * time.Second}}
	t.run(ctx, *wait)
	if t.failed > 0 {
		fmt.Printf("installtest: %d of %d checks FAILED\n", t.failed, t.checks)
		os.Exit(1)
	}
	fmt.Printf("installtest: all %d checks passed\n", t.checks)
}

type tester struct {
	core, api, tokenFile string
	http                 *http.Client
	checks, failed       int
}

func (t *tester) check(name string, ok bool, detail string) bool {
	t.checks++
	word := "PASS"
	if !ok {
		word = "FAIL"
		t.failed++
	}
	fmt.Printf("%s %s: %s\n", word, name, detail)
	return ok
}

func (t *tester) token() (string, error) {
	raw, err := os.ReadFile(t.tokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// call sends method url with body as JSON (nil: none) and decodes the answer into out (nil: discarded). It returns
// the status; a transport error is an error.
func (t *tester) call(ctx context.Context, method, url string, body any, auth bool, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		tok, err := t.token()
		if err != nil {
			return 0, fmt.Errorf("reading the token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("HTTP %d, undecodable answer %.200q: %w", resp.StatusCode, raw, err)
		}
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %.300s", resp.StatusCode, raw)
	}
	return resp.StatusCode, nil
}

// waitReady polls base/readyz until it answers 200 or wait passes.
func (t *tester) waitReady(ctx context.Context, name, base string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	var last string
	for {
		var ready struct {
			OK     bool            `json:"ok"`
			Error  string          `json:"error"`
			Policy json.RawMessage `json:"policy"`
			Head   *int64          `json:"head"`
		}
		code, err := t.call(ctx, "GET", base+"/readyz", nil, false, &ready)
		if err == nil && code == 200 && ready.OK {
			head := "n/a"
			if ready.Head != nil {
				head = fmt.Sprint(*ready.Head)
			}
			return t.check(name+".readyz", true, fmt.Sprintf("ready, policy %s, head %s", ready.Policy, head))
		}
		last = fmt.Sprintf("HTTP %d %v %s", code, err, ready.Error)
		if time.Now().After(deadline) {
			return t.check(name+".readyz", false, "not ready after "+wait.String()+": "+last)
		}
		time.Sleep(2 * time.Second)
	}
}

func (t *tester) healthz(ctx context.Context, name, base string) {
	var h struct {
		OK bool `json:"ok"`
	}
	code, err := t.call(ctx, "GET", base+"/healthz", nil, false, &h)
	t.check(name+".healthz", err == nil && code == 200 && h.OK, fmt.Sprintf("HTTP %d ok=%v %v", code, h.OK, errText(err)))
}

func (t *tester) run(ctx context.Context, wait time.Duration) {
	if !t.waitReady(ctx, "core", t.core, wait) {
		return
	}
	t.healthz(ctx, "core", t.core)

	nonce := randHex(6)
	seq, hash := t.decision(ctx, nonce)
	t.change(ctx, nonce)

	if t.api == "" {
		fmt.Println("SKIP api: no --api (the chart's api Deployment is off)")
		return
	}
	if !t.waitReady(ctx, "api", t.api, wait) {
		return
	}
	t.healthz(ctx, "api", t.api)
	t.apiReads(ctx, seq, hash)
}

// decision evaluates an allowed fake tool call, checks it was recorded, and reports its outcome. It returns the
// decision record's seq and hash ("" when there is none).
func (t *tester) decision(ctx context.Context, nonce string) (string, string) {
	session := "installtest-" + nonce
	now := time.Now().UTC().Truncate(time.Second)
	zero := map[string]int{"children": 0, "github_calls": 0, "model_tokens": 0, "open_prs": 0, "tool_calls": 0}
	ev := map[string]any{
		"subject": map[string]any{"type": "principal", "id": "user:installtest",
			"properties": map[string]any{"kind": "user", "tier_ceiling": 1}},
		"action": map[string]any{"name": "tool.call", "properties": map[string]any{"args": map[string]any{
			"repo": "installtest/app", "branch": "agent/" + session, "title": "installtest " + session,
			"files": []any{map[string]any{"path": "charts/values.yaml", "content": "replicas: 2\n"}}}}},
		"resource": map[string]any{"type": "tool", "id": "repo.pr.open"},
		"context": map[string]any{
			"now": now.Format(time.RFC3339), "session_id": session,
			"scope": map[string]any{"agent_kind": "task", "api_allow": []string{}, "deny_paths": []string{".tekton/**"},
				"field_allow": []string{}, "field_deny": []string{}, "repos_allow": []string{"installtest/*"}},
			"session": map[string]any{
				"id": session, "principal": "user:installtest", "agent": "installtest-agent", "task_id": "t-" + session,
				"parent_id": nil, "depth": 0, "closed": false, "tripped": false, "denials": 0,
				"expires_at": now.Add(30 * time.Minute).Format(time.RFC3339),
				"limits": map[string]any{"tier_ceiling": "T1", "ttl_minutes": 30, "tool_calls": 200, "github_calls": 300,
					"open_prs": 3, "model_tokens": 500000, "children": 2,
					"tools":  []string{"catalog.read", "repo.file.get", "repo.pr.open"},
					"models": []string{}, "network": "clearance", "compute": "small"},
				"used": zero, "reserved": zero,
			},
		},
	}
	var res struct {
		Decision   bool    `json:"decision"`
		DecisionID *string `json:"decision_id"`
		Record     *struct {
			Seq  int64  `json:"seq"`
			Hash string `json:"hash"`
		} `json:"record"`
		Context struct {
			Rule    string `json:"rule"`
			Message string `json:"message"`
			Policy  struct {
				Bundle  string `json:"bundle"`
				Version string `json:"version"`
			} `json:"policy"`
		} `json:"context"`
	}
	code, err := t.call(ctx, "POST", t.core+"/access/v1/evaluation", ev, true, &res)
	recorded := res.DecisionID != nil && res.Record != nil && res.Record.Hash != "" &&
		*res.DecisionID == fmt.Sprint(res.Record.Seq)
	detail := fmt.Sprintf("HTTP %d decision=%v rule=%q policy=%s@%s", code, res.Decision, res.Context.Rule,
		res.Context.Policy.Bundle, res.Context.Policy.Version)
	if recorded {
		detail += fmt.Sprintf(", recorded as seq %d hash %s", res.Record.Seq, short(res.Record.Hash))
	}
	if err != nil {
		detail += ": " + err.Error()
	}
	if !t.check("decision.evaluated-and-recorded", err == nil && res.Decision && recorded, detail) {
		return "", ""
	}
	var ref struct {
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	}
	code, err = t.call(ctx, "POST", t.core+"/v1/decisions/"+*res.DecisionID+"/outcome",
		map[string]any{"result": "ok"}, true, &ref)
	t.check("decision.outcome-recorded", err == nil && ref.Seq > res.Record.Seq && ref.Hash != "",
		fmt.Sprintf("HTTP %d outcome seq %d %s", code, ref.Seq, errText(err)))
	// A second outcome for the same decision is refused.
	code, err = t.call(ctx, "POST", t.core+"/v1/decisions/"+*res.DecisionID+"/outcome",
		map[string]any{"result": "ok"}, true, nil)
	t.check("decision.outcome-once", err != nil && code == http.StatusConflict, fmt.Sprintf("second outcome: HTTP %d", code))
	return fmt.Sprint(res.Record.Seq), res.Record.Hash
}

// change registers a tier-0 change (a docs-only path, no objects) and expects the gate's policy to clear it.
func (t *tester) change(ctx context.Context, nonce string) {
	head := sha("installtest-head-" + nonce)[:40]
	body := map[string]any{"app": "installtest-app", "env": "prod", "cluster": "installtest",
		"repo": "installtest/gitops", "pr": 1, "head": head, "proposer": "user:installtest-proposer",
		"proposerKind": "person", "owner": "group:default/installtest-owners", "protected": true,
		"treeDigest": "sha256:" + sha("installtest-tree-"+nonce), "paths": []string{"docs/README.md"},
		"linesChanged": 1, "checks": map[string]string{"ci": "pass", "provenance": "not-agent", "render": "ok"}}
	var c struct {
		ID        string  `json:"id"`
		State     string  `json:"state"`
		Tier      int     `json:"tier"`
		ClearedBy *string `json:"cleared_by"`
	}
	code, err := t.call(ctx, "POST", t.core+"/v1/clearances", body, true, &c)
	by := "<nil>"
	if c.ClearedBy != nil {
		by = *c.ClearedBy
	}
	t.check("change.cleared-by-policy", err == nil && c.State == "cleared" && by == "policy" && c.Tier <= 1,
		fmt.Sprintf("HTTP %d change %s tier %d state %q cleared_by %s %s", code, c.ID, c.Tier, c.State, by, errText(err)))
}

// apiReads reads the decision record and the chain's verdict from clearance-api.
func (t *tester) apiReads(ctx context.Context, seq, hash string) {
	var rec map[string]any
	if seq != "" {
		code, err := t.call(ctx, "GET", t.api+"/v1/evidence/"+seq, nil, true, &rec)
		got, _ := rec["hash"].(string)
		if got == "" {
			if r, ok := rec["record"].(map[string]any); ok {
				got, _ = r["hash"].(string)
			}
		}
		t.check("api.decision-record", err == nil && got == hash,
			fmt.Sprintf("HTTP %d seq %s hash %s (want %s) %s", code, seq, short(got), short(hash), errText(err)))
	}
	var v struct {
		OK    bool   `json:"ok"`
		Count int64  `json:"count"`
		Head  string `json:"head"`
	}
	code, err := t.call(ctx, "GET", t.api+"/v1/evidence/verify", nil, true, &v)
	t.check("api.chain-verify", err == nil && v.OK && v.Count >= 3,
		fmt.Sprintf("HTTP %d ok=%v count=%d head=%s %s", code, v.OK, v.Count, short(v.Head), errText(err)))
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
