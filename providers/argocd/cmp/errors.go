package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/argosrc"
)

// Error classes (hardening F4). Every error `generate` returns is a *CmpError of exactly one class, with a stable code,
// so a person reading Argo CD's ComparisonError, and the plugin itself, can tell them apart:
//
//	fault    the plugin failed: a bug (a panic), its own I/O, a tool that could not start or was killed, a timeout, a
//	         sidecar setting. Not the Application's doing and not a decision. Only a fault before the decision may
//	         fall back to the last-known-good render (lkg.go), and only when that is turned on.
//	dependency  something the render needs is unavailable: git or the chart's host cannot be reached, or the chart
//	         cannot be fetched after its tag resolved. Not the Application's doing and not a decision. May fall back to
//	         the last-known-good render, as a fault does.
//	render   the Application's inputs do not render as given: Helm or kustomize said no, a source the platform does
//	         not allow, a symlink that leaves its repository, a tree that cannot be hashed, a bad parameter. Never
//	         falls back: the same inputs would fail the same way.
//	refusal  Clearance said no: a denied, expired or superseded change, an outage hold, the core refusing the
//	         registration. Never falls back: a decision is never worked around.
//
// The codes are part of the plugin's interface (docs/install-argocd-plugin.md, "Error codes"): a code is never renamed
// or reused for another meaning; a new case gets a new code.
type ErrClass string

const (
	ClassFault   ErrClass = "fault"
	ClassDep     ErrClass = "dependency"
	ClassRender  ErrClass = "render"
	ClassRefusal ErrClass = "refusal"
)

// The stable codes. The prefix names the class.
const (
	CodeFaultPanic        = "CMP-FAULT-PANIC"         // the plugin panicked; recovered
	CodeFaultInternal     = "CMP-FAULT-INTERNAL"      // the plugin's own failure it has no more specific code for (scratch I/O, an unexpected error)
	CodeFaultTool         = "CMP-FAULT-TOOL"          // helm, kustomize or git could not be started, or was killed by a signal
	CodeFaultTimeout      = "CMP-FAULT-TIMEOUT"       // the render ran out of time
	CodeFaultSandbox      = "CMP-FAULT-SANDBOX"       // CLEARANCE_CMP_NETNS=require and the private network namespace cannot be created
	CodeFaultConfig       = "CMP-FAULT-CONFIG"        // a sidecar setting (CLEARANCE_*) is missing or malformed
	CodeFaultToken        = "CMP-FAULT-TOKEN"         // the token file could not be read; nothing was sent
	CodeFaultCoreResponse = "CMP-FAULT-CORE-RESPONSE" // the core answered something the plugin cannot read
	CodeFaultWaitImage    = "CMP-FAULT-WAIT-IMAGE"    // a change is held but CLEARANCE_WAIT_IMAGE is not set
	CodeFaultBusy         = "CMP-FAULT-BUSY"          // every render slot (CLEARANCE_CMP_MAX_RENDERS) stayed busy for the render's wall time

	CodeDepChartUnreachable = "CMP-DEP-CHART-UNREACHABLE" // git or the chart's host could not be reached to resolve the tag
	CodeDepChartFetch       = "CMP-DEP-CHART-FETCH"       // the chart's tag resolved on the remote, but the fetch then failed

	CodeRenderParams    = "CMP-RENDER-PARAMS"       // a plugin parameter (PARAM_*) or Argo CD variable is missing or malformed
	CodeRenderRefused   = "CMP-RENDER-REFUSED"      // a source the platform does not allow, or a symlink or path that leaves its repository
	CodeRenderFetch     = "CMP-RENDER-FETCH"        // the chart's tag did not resolve on the remote (no such tag, a private or unreachable repository)
	CodeRenderHelm      = "CMP-RENDER-HELM"         // helm template failed on the chart and values
	CodeRenderKustomize = "CMP-RENDER-KUSTOMIZE"    // kustomize build failed
	CodeRenderSources   = "CMP-RENDER-SOURCES"      // generic mode: the Application's sources do not render, or use a feature the plugin refuses
	CodeRenderTree      = "CMP-RENDER-TREE"         // the render cannot be hashed (no objects, too many, a duplicate, an ambiguous YAML scalar)
	CodeRenderRevision  = "CMP-RENDER-REVISION"     // ARGOCD_APP_REVISION is not a commit, or the source repository has no owner/name
	CodeRenderLimitCPU  = "CMP-RENDER-LIMIT-CPU"    // a render step used more CPU than CLEARANCE_CMP_RENDER_MAX_CPU
	CodeRenderLimitMem  = "CMP-RENDER-LIMIT-MEMORY" // a render step needed more memory than CLEARANCE_CMP_RENDER_MAX_MEMORY
	CodeRenderLimitOut  = "CMP-RENDER-LIMIT-OUTPUT" // a step's output, or the manifests, went over CLEARANCE_CMP_RENDER_MAX_OUTPUT
	CodeRenderLimitTemp = "CMP-RENDER-LIMIT-TEMP"   // the render's scratch space, or one file, went over CLEARANCE_CMP_RENDER_MAX_TEMP

	CodeRefusedDenied     = "CMP-REFUSED-DENIED"      // the change is denied
	CodeRefusedExpired    = "CMP-REFUSED-EXPIRED"     // the change's clearance expired
	CodeRefusedSuperseded = "CMP-REFUSED-SUPERSEDED"  // a newer change replaced it
	CodeRefusedException  = "CMP-REFUSED-EXCEPTION"   // the change is under a deploy exception, not cleared
	CodeRefusedDegraded   = "CMP-REFUSED-DEGRADED"    // the change is in degraded mode, not cleared
	CodeRefusedState      = "CMP-REFUSED-STATE"       // the change is in another state that does not sync
	CodeRefusedOutageHold = "CMP-REFUSED-OUTAGE-HOLD" // the core is unreachable and nothing cleared and allow-and-record is remembered
	CodeRefusedByCore     = "CMP-REFUSED-BY-CORE"     // the core refused the registration (4xx: the token, not a verifier, a bad request)
)

// Codes is every code with its class, for the docs test and the table in the install guide.
var Codes = map[string]ErrClass{
	CodeFaultPanic: ClassFault, CodeFaultInternal: ClassFault, CodeFaultTool: ClassFault, CodeFaultTimeout: ClassFault,
	CodeFaultSandbox: ClassFault, CodeFaultConfig: ClassFault, CodeFaultToken: ClassFault,
	CodeFaultCoreResponse: ClassFault, CodeFaultWaitImage: ClassFault, CodeFaultBusy: ClassFault,
	CodeDepChartUnreachable: ClassDep, CodeDepChartFetch: ClassDep,
	CodeRenderParams: ClassRender, CodeRenderRefused: ClassRender, CodeRenderFetch: ClassRender, CodeRenderHelm: ClassRender,
	CodeRenderKustomize: ClassRender, CodeRenderSources: ClassRender, CodeRenderTree: ClassRender, CodeRenderRevision: ClassRender,
	CodeRenderLimitCPU: ClassRender, CodeRenderLimitMem: ClassRender, CodeRenderLimitOut: ClassRender, CodeRenderLimitTemp: ClassRender,
	CodeRefusedDenied: ClassRefusal, CodeRefusedExpired: ClassRefusal, CodeRefusedSuperseded: ClassRefusal,
	CodeRefusedException: ClassRefusal, CodeRefusedDegraded: ClassRefusal, CodeRefusedState: ClassRefusal,
	CodeRefusedOutageHold: ClassRefusal, CodeRefusedByCore: ClassRefusal,
}

// CmpError is what `generate` fails with. Its message (hardening U1) is one short first line, "<code>: <summary>", then
// the link to the change when there is one ("hold: <url>"), then the full detail. Argo CD shows all of it as the
// Application's ComparisonError.
type CmpError struct {
	Class   ErrClass
	Code    string
	Summary string // one short line, no newline
	Link    string // the change's page (refusals and held changes), "" when there is no change
	Err     error  // the detail: the underlying error, kept for errors.Is/As
}

func (e *CmpError) Error() string {
	var b strings.Builder
	b.WriteString(e.Code + ": " + e.Summary)
	if e.Link != "" {
		b.WriteString("\nhold: " + e.Link)
	}
	if e.Err != nil {
		if d := e.Err.Error(); d != e.Summary {
			b.WriteString("\ndetail: " + d)
		}
	}
	return b.String()
}

func (e *CmpError) Unwrap() error { return e.Err }

// FallsBack is whether the last-known-good render may answer this error: a plugin fault or an unavailable
// dependency, never a render error or a refusal.
func (e *CmpError) FallsBack() bool { return e.Class == ClassFault || e.Class == ClassDep }

// FirstLine is the error's first line, what a list of Applications shows.
func (e *CmpError) FirstLine() string { return e.Code + ": " + e.Summary }

// maxFirstLine bounds "<code>: <summary>" (U1): a longer summary is cut, the whole message stays in Err.
const maxFirstLine = 120

func newErr(code, summary string, err error) *CmpError {
	summary = strings.ReplaceAll(summary, "\n", " ")
	if room := maxFirstLine - len(code) - 2; len(summary) > room {
		cut := room - 3
		for cut > 0 && !utf8.RuneStart(summary[cut]) {
			cut--
		}
		if err == nil {
			err = errors.New(summary)
		} else if !strings.Contains(err.Error(), summary) {
			err = fmt.Errorf("%s: %w", summary, err) // the whole summary stays in the detail; errors.Is/As still see err
		}
		summary = summary[:cut] + "..."
	}
	return &CmpError{Class: Codes[code], Code: code, Summary: summary, Err: err}
}

// asCmp returns err's *CmpError, if it has one.
func asCmp(err error) (*CmpError, bool) {
	var ce *CmpError
	ok := errors.As(err, &ce)
	return ce, ok
}

// classifyRender is the class and code of an error from the render phase (the fetch, Helm, kustomize, the generic
// renderer). An error the plugin cannot place is a fault: the render's own failures are recognised by what they are,
// so an unknown one is the plugin's.
//
//	lookup    what the lookup of the chart's tag said this run (a fetch that fails after it resolved, or after the host
//	          could not be reached, is a dependency's failure; after "no such ref" it is the Application's)
//	generic   generic mode, whose renderer's own errors name their source ("source N: ...")
func classifyRender(ctx context.Context, err error, lookup chartLookupResult, generic bool) *CmpError {
	if ce, ok := asCmp(err); ok {
		return ce
	}
	// A render limit (limits.go): its code says which, and so its class (a fault for the time and the slots, which a
	// slow network or a busy sidecar can cause; a render error for the rest, which the same inputs reach again).
	var le *LimitError
	if errors.As(err, &le) {
		return newErr(le.Code(), le.Summary(), err)
	}
	msg := err.Error()
	var ne *netnsError
	var ee *exec.Error
	var xe *exec.ExitError
	var pe *fs.PathError
	switch {
	case errors.As(err, &ne) && strings.Contains(msg, FSSandboxEnv+"="+NetnsRequire):
		return newErr(CodeFaultSandbox, "the render steps cannot get the filesystem sandbox (CLEARANCE_CMP_FS_SANDBOX=require)", err)
	case errors.As(err, &ne):
		return newErr(CodeFaultSandbox, "the render steps cannot get a private network namespace (CLEARANCE_CMP_NETNS=require)", err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), ctx.Err() != nil:
		return newErr(CodeFaultTimeout, "the render ran out of time", err)
	case errors.As(err, &ee):
		return newErr(CodeFaultTool, "a render tool could not be started", err)
	case errors.As(err, &xe) && xe.ProcessState != nil && !xe.Exited():
		return newErr(CodeFaultTool, "a render tool was killed before it finished", err)
	case isKind(err, kindNoRepos):
		return newErr(CodeFaultConfig, "CLEARANCE_CHART_REPOS is not set on the sidecar: no chart may be fetched", err)
	case isKind(err, kindRefused):
		return newErr(CodeRenderRefused, "a source or path the plugin refuses to read", err)
	case errors.As(err, &pe) && !generic:
		return newErr(CodeFaultInternal, "the plugin could not use its scratch files", err)
	case isKind(err, kindChartFetch):
		return classifyChartFetch(err, lookup)
	case isKind(err, kindHelm):
		return newErr(CodeRenderHelm, "helm template failed on the chart and values", err)
	case isKind(err, kindKustomize):
		return newErr(CodeRenderKustomize, "kustomize build failed", err)
	case generic && argosrc.IsSources(err):
		return newErr(CodeRenderSources, "the Application's sources do not render", err)
	}
	return classifyRenderByMessage(err, msg, generic, lookup)
}

func classifyChartFetch(err error, lookup chartLookupResult) *CmpError {
	switch lookup {
	case lookupResolved:
		return newErr(CodeDepChartFetch, "the chart's tag resolved but its fetch failed", err)
	case lookupUnreachable:
		return newErr(CodeDepChartUnreachable, "git or the chart's host cannot be reached", err)
	case lookupNoRef:
		return newErr(CodeRenderFetch, "the chart's tag does not exist on its repository", err)
	}
	return newErr(CodeRenderFetch, "the chart cannot be fetched at its tag", err)
}

// renderKind is what a render-phase error is, stated where it is made (I-76). classifyRender reads it with errors.As
// instead of guessing from the message's first words, so rewording a message cannot change its code.
type renderKind int

const (
	kindRefused    renderKind = iota + 1 // a source, path or symlink the plugin refuses (CMP-RENDER-REFUSED)
	kindNoRepos                          // CLEARANCE_CHART_REPOS is not set (CMP-FAULT-CONFIG)
	kindChartFetch                       // the chart's fetch or its tag's resolution failed (the code depends on the lookup)
	kindHelm                             // helm template failed (CMP-RENDER-HELM)
	kindKustomize                        // kustomize build failed (CMP-RENDER-KUSTOMIZE)
)

// renderError carries a renderKind. Its message is the wrapped error's, unchanged.
type renderError struct {
	kind renderKind
	err  error
}

func (e *renderError) Error() string { return e.err.Error() }
func (e *renderError) Unwrap() error { return e.err }

// renderErr marks err as a render error of kind.
func renderErr(kind renderKind, err error) error { return &renderError{kind: kind, err: err} }

// renderErrf is fmt.Errorf, marked as a render error of kind.
func renderErrf(kind renderKind, format string, a ...any) error {
	return renderErr(kind, fmt.Errorf(format, a...))
}

func isKind(err error, kind renderKind) bool {
	var re *renderError
	return errors.As(err, &re) && re.kind == kind
}

// unclassifiedLog reports an error that reached classification with no typed class: a debug line (log/slog, which
// drops it unless the process turns debug on) naming the message. Replaceable by a test.
var unclassifiedLog = func(how, msg string) {
	slog.Debug("clearance: render error with no typed class", "classified_by", how, "message", msg)
}

// classifyRenderByMessage is the last resort: an error that carries no class is placed by its message's first words,
// as before typed classes (I-76). Every error the plugin makes itself is typed where it is made (renderError,
// argosrc.SourcesError), so reaching here means an error from a dependency or one added without a class; either way
// the message is logged. What it cannot place is a fault (CMP-FAULT-INTERNAL).
func classifyRenderByMessage(err error, msg string, generic bool, lookup chartLookupResult) *CmpError {
	switch {
	case strings.HasPrefix(msg, "refused: CLEARANCE_CHART_REPOS is not set"):
		unclassifiedLog("message prefix", msg)
		return newErr(CodeFaultConfig, "CLEARANCE_CHART_REPOS is not set on the sidecar: no chart may be fetched", err)
	case strings.HasPrefix(msg, "refused:"):
		unclassifiedLog("message prefix", msg)
		return newErr(CodeRenderRefused, "a source or path the plugin refuses to read", err)
	case strings.HasPrefix(msg, "fetch the chart at"), strings.HasPrefix(msg, "peel the chart tag"), strings.HasPrefix(msg, "the chart tag "):
		unclassifiedLog("message prefix", msg)
		return classifyChartFetch(err, lookup)
	case strings.HasPrefix(msg, "helm template:"):
		unclassifiedLog("message prefix", msg)
		return newErr(CodeRenderHelm, "helm template failed on the chart and values", err)
	case strings.HasPrefix(msg, "kustomize build:"):
		unclassifiedLog("message prefix", msg)
		return newErr(CodeRenderKustomize, "kustomize build failed", err)
	case generic && (strings.HasPrefix(msg, "source ") || strings.Contains(msg, "unsupported by the Clearance plugin") ||
		strings.HasPrefix(msg, "the sources") || strings.HasPrefix(msg, "the render") || strings.HasPrefix(msg, "the Application")):
		unclassifiedLog("message prefix", msg)
		return newErr(CodeRenderSources, "the Application's sources do not render", err)
	}
	unclassifiedLog("fallback", msg)
	return newErr(CodeFaultInternal, "the plugin failed while rendering", err)
}

// chartLookupResult is what Generate's lookup of the chart's tag said.
type chartLookupResult int

const (
	lookupNotAsked    chartLookupResult = iota // no lookup this run (no cache wanted it, or no chart repository)
	lookupResolved                             // the remote named a commit
	lookupNoRef                                // the remote answered without the ref
	lookupUnreachable                          // git could not run or reach the remote
)

func chartLookup(cfg Config) chartLookupResult {
	switch {
	case !cfg.chartLooked:
		return lookupNotAsked
	case cfg.chartCommit != "":
		return lookupResolved
	case cfg.chartLookupErr != nil:
		return lookupUnreachable
	}
	return lookupNoRef
}

// classifyConfig is the code of a ParseConfig error: a sidecar setting (every such message starts with its CLEARANCE_
// name) is the platform's fault; otherwise it is a parameter or variable of this Application.
func classifyConfig(err error) *CmpError {
	for _, e := range flatten(err) {
		if strings.HasPrefix(e.Error(), "CLEARANCE_") {
			return newErr(CodeFaultConfig, "a sidecar setting is missing or malformed", err)
		}
	}
	return newErr(CodeRenderParams, "a plugin parameter or Argo CD variable is missing or malformed", err)
}

// classifyCore is the code of a RegisterChange error that is not an outage.
func classifyCore(err error) *CmpError {
	var ae *client.APIError
	switch {
	case errors.Is(err, client.ErrToken):
		return newErr(CodeFaultToken, "the plugin's token could not be read; nothing was sent", err)
	case errors.Is(err, client.ErrBadResponse):
		return newErr(CodeFaultCoreResponse, "the core's answer could not be read", err)
	case errors.As(err, &ae):
		return newErr(CodeRefusedByCore, fmt.Sprintf("the core refused the registration (HTTP %d)", ae.Status), fmt.Errorf("clearance refused the change: %w", err))
	}
	return newErr(CodeFaultInternal, "the call to the core failed", err)
}

// stateCode is the refusal code of a change state that does not sync.
func stateCode(state string) string {
	switch state {
	case "denied":
		return CodeRefusedDenied
	case "expired":
		return CodeRefusedExpired
	case "superseded":
		return CodeRefusedSuperseded
	case "exception":
		return CodeRefusedException
	case "degraded":
		return CodeRefusedDegraded
	}
	return CodeRefusedState
}

var changeIDRx = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ChangeLink is the page of a change: CLEARANCE_CMP_LINK_BASE + "/changes/" + id (the web UI, as the GRC push links
// it) when set, otherwise the core's own record, CLEARANCE_URL + "/v1/clearances/" + id. "" for an id that is not a
// plain identifier (it is the core's, but it is never put in a link unchecked).
func ChangeLink(cfg Config, id string) string {
	if !changeIDRx.MatchString(id) {
		return ""
	}
	if cfg.LinkBase != "" {
		return strings.TrimRight(cfg.LinkBase, "/") + "/changes/" + url.PathEscape(id)
	}
	if cfg.CoreURL == "" {
		return ""
	}
	return strings.TrimRight(cfg.CoreURL, "/") + "/v1/clearances/" + url.PathEscape(id)
}

// refusal is a refusal of change id: its link is the change's page.
func refusal(cfg Config, code, summary, id string, err error) *CmpError {
	e := newErr(code, summary, err)
	e.Link = ChangeLink(cfg, id)
	return e
}
