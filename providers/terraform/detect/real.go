package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// Terraform runs the terraform binary: plan -detailed-exitcode -lock=false (it must not hold the state lock a
// real apply wants), the plan saved to a private temp directory and read back with `show -json` only to name the
// addresses. The plan file is removed with its directory. The binary needs read access to the state and to the
// providers' APIs; it is never given apply rights by this command.
type Terraform struct {
	Bin string // default "terraform"
}

// Plan implements Planner.
func (t Terraform) Plan(ctx context.Context, ws Workspace) (int, []string, error) {
	bin := t.Bin
	if bin == "" {
		bin = "terraform"
	}
	tmp, err := os.MkdirTemp("", "tfdetect-")
	if err != nil {
		return 0, nil, err
	}
	defer os.RemoveAll(tmp)
	file := filepath.Join(tmp, "plan")
	cmd := exec.CommandContext(ctx, bin, "plan", "-detailed-exitcode", "-input=false", "-lock=false", "-no-color", "-out="+file)
	cmd.Dir = ws.Dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_WORKSPACE="+ws.Name)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil, nil
	case errors.As(err, &ee) && ee.ExitCode() == 2:
	default:
		return 1, nil, fmt.Errorf("terraform plan failed: %s", tail(out))
	}
	show := exec.CommandContext(ctx, bin, "show", "-json", "-no-color", file)
	show.Dir = ws.Dir
	show.Env = cmd.Env
	js, err := show.Output()
	if err != nil {
		return 2, nil, fmt.Errorf("terraform show: %w", err)
	}
	return 2, AddressesOf(js), nil
}

func tail(b []byte) string {
	if len(b) > 400 {
		b = b[len(b)-400:]
	}
	return strings.TrimSpace(string(b))
}

// AddressesOf is the resource addresses a plan's JSON changes (anything but no-op and read).
func AddressesOf(planJSON []byte) []string {
	var p struct {
		RC []struct {
			Address string `json:"address"`
			Change  struct {
				Actions []string `json:"actions"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if json.Unmarshal(planJSON, &p) != nil {
		return nil
	}
	var out []string
	for _, r := range p.RC {
		a := r.Change.Actions
		if len(a) == 1 && (a[0] == "no-op" || a[0] == "read") {
			continue
		}
		out = append(out, r.Address)
	}
	return out
}

// HTTPEvidence reads clearance-api (GET /v1/evidence, GET /v1/exceptions) as the detector's identity: a bearer
// token read fresh for each request. The detector's principal needs a role that may read evidence (auditor).
type HTTPEvidence struct {
	Base  string
	Token client.TokenSource
	HTTP  *http.Client
}

const maxEvidence = 32 << 20

func (e *HTTPEvidence) page(ctx context.Context, path string, q url.Values) ([]map[string]any, error) {
	var all []map[string]any
	for i := 0; i < 20; i++ {
		tok, err := e.Token.Token(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(e.Base, "/")+path+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		hc := e.HTTP
		if hc == nil {
			hc = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxEvidence+1))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 || len(b) > maxEvidence {
			return nil, fmt.Errorf("GET %s: %d %s", path, resp.StatusCode, clip(b))
		}
		var pg struct {
			Items []map[string]any `json:"items"`
			Next  *int64           `json:"next"`
		}
		if err := json.Unmarshal(b, &pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Items...)
		if pg.Next == nil {
			return all, nil
		}
		q.Set("after", fmt.Sprint(*pg.Next))
	}
	return nil, errors.New("clearance-api: over 20 pages")
}

func str(m map[string]any, k ...string) string {
	var v any = m
	for _, x := range k {
		mm, _ := v.(map[string]any)
		v = mm[x]
	}
	s, _ := v.(string)
	return s
}

// Outcomes is the deploy.outcome records since the time: their environment and apply window.
func (e *HTTPEvidence) Outcomes(ctx context.Context, since time.Time) ([]Outcome, error) {
	items, err := e.page(ctx, "/v1/evidence", url.Values{"tool": {"deploy.outcome"}, "since": {since.UTC().Format(time.RFC3339)}, "limit": {"200"}})
	if err != nil {
		return nil, err
	}
	var out []Outcome
	for _, r := range items {
		s, err1 := time.Parse(time.RFC3339, str(r, "outcome", "started_at"))
		f, err2 := time.Parse(time.RFC3339, str(r, "outcome", "finished_at"))
		if err1 != nil || err2 != nil {
			continue // an outcome with no apply window (a manifest change's) explains no state write
		}
		out = append(out, Outcome{str(r, "destination", "environment"), s, f})
	}
	return out, nil
}

// Reported is the deploy.exception records of kind drift and untraced-apply since the time (the detector's own).
func (e *HTTPEvidence) Reported(ctx context.Context, since time.Time) ([]Reported, error) {
	items, err := e.page(ctx, "/v1/exceptions", url.Values{"tool": {"deploy.exception"}, "since": {since.UTC().Format(time.RFC3339)}, "limit": {"200"}})
	if err != nil {
		return nil, err
	}
	var out []Reported
	for _, r := range items {
		k := str(r, "exception", "kind")
		if k != "drift" && k != "untraced-apply" {
			continue
		}
		out = append(out, Reported{Kind: k, Backend: str(r, "destination", "workspace", "backend"),
			Key: str(r, "destination", "workspace", "key"), Name: str(r, "destination", "workspace", "name"), Version: str(r, "exception", "state", "version"),
			Fingerprint: str(r, "exception", "observed")})
	}
	return out, nil
}
