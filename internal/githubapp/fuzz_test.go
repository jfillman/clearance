package githubapp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/githubapp"
)

// FuzzWebhookPayload: any body, signed or not, under any event name, is answered without panicking; only a correct
// signature gets past 401; and a deployment_protection_rule payload never sends the App's token to a URL it names
// (the fake GitHub sees no review unless the callback is its own).
func FuzzWebhookPayload(f *testing.F) {
	f.Add("pull_request", []byte(`{"action":"opened","installation":{"id":9},"repository":{"full_name":"a/b"},"pull_request":{"number":1}}`), true)
	f.Add("deployment_protection_rule", []byte(`{"action":"requested","environment":"prod","deployment":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"deployment_callback_url":"https://evil.example/repos/a/b/actions/runs/1/deployment_protection_rule","repository":{"full_name":"a/b"},"installation":{"id":9}}`), true)
	f.Add("installation", []byte(`{"action":"created","installation":{"id":"x","account":[]},"repositories":[1,{"full_name":null}]}`), true)
	f.Add("check_run", []byte(`{"action":"rerequested","check_run":{"name":"Clearance / agent-scope","pull_requests":[{"number":1.5}]}}`), false)
	f.Add("x", []byte(`[]`), true)
	f.Fuzz(func(t *testing.T, event string, body []byte, signed bool) {
		e := newEnv(t)
		fake := newFake(t, "alice", nil, head)
		a := e.app(t, fake, "off")
		sig := ""
		if signed {
			sig = sign(body)
		}
		status, _ := a.Accept(event, body, sig)
		if !signed && status != 401 {
			t.Fatalf("unsigned body answered %d", status)
		}
		if status != 202 {
			return
		}
		payload, err := decodeForFuzz(body)
		if err != nil {
			t.Fatal("queued a body that is not a JSON object")
		}
		if event == "deployment_protection_rule" {
			_, _ = a.Handle(context.Background(), event, payload)
			cb, _ := payload["deployment_callback_url"].(string)
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if !strings.HasPrefix(cb, fake.srv.URL+"/") && len(fake.calls) > 0 {
				t.Fatalf("a callback outside the API (%q) led to %d GitHub calls", cb, len(fake.calls))
			}
		}
		_ = githubapp.Wanted(event, payload)
	})
}
