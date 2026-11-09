// Package conformance is the provider conformance harness: `clearance conformance --provider <url>` starts an
// in-memory core and a fake target, drives the provider through its test-only control interface, and proves the
// provider follows the protocol in docs/provider-protocol.md.
//
// A provider is an enforcement point that asks the core for decisions and writes its records through it. Two
// roles are tested:
//
//   - runtime (the Autopilot gateway): evaluate before acting, act only on allow, apply the spend, report the
//     outcome, fail closed when the core is unreachable;
//   - deployment (the Argo CD gate, the Terraform gate, the GitHub App's deployment protection rule): register the
//     change with its subject digest, hold until cleared, release on clear, refuse on deny or expiry, and report a
//     deploy.outcome whose digest is the cleared subject's.
//
// This file is the control interface a provider exposes for testing only (off by default; docs/provider-protocol.md
// says how to guard it). harness.go is the harness, target.go the fake target, report.go the report.
package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
)

// SuiteVersion names this assertion set. It changes when an assertion is added, removed or tightened; it is the
// value a provider's evidence record may carry as provider.conformance once the core can stamp it.
const SuiteVersion = "clearance-conformance/v1"

// The control interface's paths, on the provider's control address.
const (
	PathInfo    = "/conformance/v1/info"
	PathApply   = "/conformance/v1/apply"
	PathApplies = "/conformance/v1/applies/" // + {id}
)

// The fake target's path, on the target address the harness hands the provider.
const PathTargetApply = "/v1/apply"

// Roles.
const (
	RoleRuntime    = "runtime"
	RoleDeployment = "deployment"
)

// Apply states a provider reports. accepted and holding are in flight; applied, refused and failed are terminal.
const (
	StateAccepted = "accepted" // taken, not yet decided
	StateHolding  = "holding"  // deployment: registered, the change holds; nothing applied
	StateApplied  = "applied"  // acted on the target
	StateRefused  = "refused"  // deliberately did not act: a deny, an expiry, an unreachable core
	StateFailed   = "failed"   // tried to act and could not (the target refused it)
)

// Terminal reports whether a provider is done with an apply in this state.
func Terminal(state string) bool {
	return state == StateApplied || state == StateRefused || state == StateFailed
}

// Body caps of the control interface and the fake target.
const (
	MaxControlBody = 1 << 20
	MaxTargetBody  = 1 << 20
)

// Info is GET /conformance/v1/info: who the provider is and which roles it can be tested in. The harness registers
// the provider in the core under Name and Version (CLEARANCE_PROVIDERS), so its records carry them.
type Info struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Roles   []string `json:"roles"`
	// Flow is a deployment provider's flow (flows.go): omitted for one that registers the change it is given.
	Flow string `json:"flow,omitempty"`
	// Stamps (pushed-tree) are the annotations the provider adds to the objects it applies after it took their
	// digest; the target leaves them out when it digests what it received.
	Stamps []string `json:"stamps,omitempty"`
}

// Endpoint is where the provider sends its normal traffic during the test, and the bearer token it presents there.
// The bearer is minted by the harness for this run only; a provider never logs or keeps it.
type Endpoint struct {
	URL    string `json:"url"`
	Bearer string `json:"bearer,omitempty"`
}

// ApplyRequest is POST /conformance/v1/apply: perform your normal flow once, against this core and this target.
type ApplyRequest struct {
	// ID names this apply; the target and the status use it. Lowercase letters, digits and dashes.
	ID   string `json:"id"`
	Role string `json:"role"`
	// Core is the core to ask (decisions, gate routes, records); Provider is the name it is registered under.
	Core     Endpoint `json:"core"`
	Provider string   `json:"provider"`
	// Target is what the provider acts on: the tool backend (runtime) or the environment (deployment).
	Target Endpoint `json:"target"`
	// PollIntervalMS is a hint for a deployment provider's polling of a holding change (the core serves no wait
	// route yet). A provider may poll more slowly, but the harness's hold window assumes at most a few seconds.
	PollIntervalMS int `json:"poll_interval_ms,omitempty"`

	// Evaluation (runtime) is the AuthZEN evaluation the provider sends POST /access/v1/evaluation for this call,
	// exactly: in production the gateway builds it from the session it holds; here the harness builds it so it
	// controls what the core decides. The tool's arguments (action.properties.args) are what the provider sends
	// the target when it acts.
	Evaluation json.RawMessage `json:"evaluation,omitempty"`

	// Change (deployment) is the change registration the provider sends POST /v1/clearances (gate.ChangeRequest,
	// docs/gate.md). Manifest is the rendered tree the provider applies when the change is cleared; its sha256 is
	// the change's treeDigest.
	Change   json.RawMessage `json:"change,omitempty"`
	Manifest string          `json:"manifest,omitempty"`
}

// RecordRef names a record in the core's chain.
type RecordRef struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// Status is GET /conformance/v1/applies/{id}: where the provider is with one apply.
type Status struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// DecisionID (runtime) is the decision_id the core answered.
	DecisionID string `json:"decision_id,omitempty"`
	// Spend (runtime) is the spend the provider applied to its session for this decision: the decision's
	// context.spend, as the provider applied it.
	Spend json.RawMessage `json:"spend,omitempty"`
	// ChangeID (deployment) is the change id the core answered.
	ChangeID string `json:"change_id,omitempty"`
	// Outcome is the outcome record the provider wrote, if any.
	Outcome *RecordRef `json:"outcome,omitempty"`
}

// TargetApply is the fake target's body: what the provider applies. For a deployment, Content is the rendered
// manifest; for a runtime call, the tool's arguments as JSON.
type TargetApply struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// TargetReceipt is the fake target's answer: the digest of what it received and its own sequence number.
type TargetReceipt struct {
	Seq    int64  `json:"seq"`
	SHA256 string `json:"sha256"`
}

var idRx = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}\z`)

// ValidID reports whether id is an apply id.
func ValidID(id string) bool { return idRx.MatchString(id) }

// DecodeApply strictly decodes and validates an ApplyRequest (at most MaxControlBody bytes; unknown fields,
// trailing data and a malformed field are errors).
func DecodeApply(r io.Reader) (ApplyRequest, error) {
	var a ApplyRequest
	if err := StrictDecode(r, MaxControlBody, &a); err != nil {
		return a, err
	}
	if !ValidID(a.ID) {
		return a, errors.New("id is 1 to 64 lowercase letters, digits and dashes")
	}
	if err := httpURL("core.url", a.Core.URL); err != nil {
		return a, err
	}
	if err := httpURL("target.url", a.Target.URL); err != nil {
		return a, err
	}
	if a.Provider == "" || len(a.Provider) > 63 {
		return a, errors.New("provider is the registered provider name")
	}
	if len(a.Core.Bearer) > 4096 || len(a.Target.Bearer) > 4096 {
		return a, errors.New("a bearer is at most 4096 bytes")
	}
	if a.PollIntervalMS < 0 || a.PollIntervalMS > 60_000 {
		return a, errors.New("poll_interval_ms is 0 to 60000")
	}
	switch a.Role {
	case RoleRuntime:
		if !jsonObject(a.Evaluation) || a.Change != nil || a.Manifest != "" {
			return a, errors.New("a runtime apply carries evaluation (an object) and no change or manifest")
		}
	case RoleDeployment:
		if !jsonObject(a.Change) || a.Manifest == "" || a.Evaluation != nil {
			return a, errors.New("a deployment apply carries change (an object) and manifest, and no evaluation")
		}
	default:
		return a, fmt.Errorf("role is %s or %s", RoleRuntime, RoleDeployment)
	}
	return a, nil
}

func jsonObject(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 1 && raw[0] == '{'
}

func httpURL(name, v string) error {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || len(v) > 2048 {
		return fmt.Errorf("%s is an http(s) URL without credentials, query or fragment", name)
	}
	return nil
}

// ErrTooLarge is a body over its cap.
var ErrTooLarge = errors.New("the body is over its cap")

// StrictDecode decodes exactly one JSON value of at most max bytes into v: unknown fields, trailing data and wrong
// types are errors.
func StrictDecode(r io.Reader, max int64, v any) error {
	raw, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > max {
		return ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
