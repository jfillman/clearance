package traefikhub

import (
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jfillman/clearance/client"
)

// The record this adapter writes.
const (
	ProviderName       = "traefik-hub"
	Kind               = "federated.decision"
	CoverageObserved   = "observed-not-attributed"
	CoverageAttributed = "authorized-and-verified"

	// DefaultTaskHeader is the request header the default Correlator reads from the access record
	// (request_X-Clearance-Task-Id): the caller stamps it, Hub keeps it (accessLog.fields.headers.names).
	DefaultTaskHeader = "X-Clearance-Task-Id"
	// DefaultAgentHeader is the request header named in Traefik's published access-record example.
	DefaultAgentHeader = "X-Evidence-Agent"
)

// Correlator gives the task_id a trace belongs to, from the trace's access records ("" when it cannot say).
type Correlator interface {
	TaskID(traceID string, access []Access) string
}

// HeaderCorrelator reads a task id header kept in the access records. Every record of the trace that names one
// must name the same one; a trace whose records disagree is not correlated.
type HeaderCorrelator struct{ Header string }

// TaskID implements Correlator.
func (h HeaderCorrelator) TaskID(_ string, access []Access) string {
	name := h.Header
	if name == "" {
		name = DefaultTaskHeader
	}
	task := ""
	for i := range access {
		v := strings.TrimSpace(access[i].Header(name))
		switch {
		case v == "":
		case task == "":
			task = v
		case v != task:
			return ""
		}
	}
	return task
}

// MapCorrelator is a trace id to task id table another source supplies (a gateway that recorded the traceparent
// it sent).
type MapCorrelator map[string]string

// TaskID implements Correlator.
func (m MapCorrelator) TaskID(traceID string, _ []Access) string { return m[traceID] }

// Options configure Ingest.
type Options struct {
	// Correlator finds a trace's task_id; nil is HeaderCorrelator{DefaultTaskHeader}.
	Correlator Correlator
	// AgentHeader is the kept request header naming the agent; "" is DefaultAgentHeader, "-" reads none.
	AgentHeader string
	// PrincipalHeader is a kept request header naming the caller, read when ClientUsername is unset ("" reads none).
	PrincipalHeader string
}

// Stats is what one Ingest read and wrote.
type Stats struct {
	Decisions  ReadStats `json:"decisions"`
	Access     ReadStats `json:"access"`
	Records    int       `json:"records"`
	Paired     int       `json:"paired"`     // joined to exactly one access record
	Correlated int       `json:"correlated"` // with a task_id
	NoTrace    int       `json:"no_trace"`   // a decision with no trace_id (tracing off in Hub)
}

// Ingest reads a Hub log and an access log and returns one federated.decision record per decision, in log order.
// access may be nil (decisions only: nothing is paired or correlated).
func Ingest(decisions, access io.Reader, opt Options) ([]client.RecordRequest, Stats, error) {
	var st Stats
	ds, dst, err := ParseDecisions(decisions)
	st.Decisions = dst
	if err != nil {
		return nil, st, err
	}
	var as []Access
	if access != nil {
		var ast ReadStats
		as, ast, err = ParseAccess(access)
		st.Access = ast
		if err != nil {
			return nil, st, err
		}
	}
	return Join(ds, as, opt, st)
}

// Join builds the records from parsed decisions and access records.
func Join(ds []Decision, as []Access, opt Options, st Stats) ([]client.RecordRequest, Stats, error) {
	corr := opt.Correlator
	if corr == nil {
		corr = HeaderCorrelator{Header: DefaultTaskHeader}
	}
	agentHeader := opt.AgentHeader
	if agentHeader == "" {
		agentHeader = DefaultAgentHeader
	}
	byTrace := map[string][]Access{}
	for _, a := range as {
		byTrace[a.Trace()] = append(byTrace[a.Trace()], a)
	}
	decisionsIn := map[string]int{}
	for _, d := range ds {
		if d.TraceID != "" {
			decisionsIn[d.TraceID]++
		}
	}
	tasks := map[string]string{}
	out := make([]client.RecordRequest, 0, len(ds))
	for _, d := range ds {
		var trace []Access
		var paired *Access
		task := ""
		if d.TraceID == "" {
			st.NoTrace++
		} else {
			trace = byTrace[d.TraceID]
			if len(trace) == 1 && decisionsIn[d.TraceID] == 1 {
				paired = &trace[0]
			}
			t, seen := tasks[d.TraceID]
			if !seen {
				t = clean(corr.TaskID(d.TraceID, trace))
				tasks[d.TraceID] = t
			}
			task = t
		}
		out = append(out, record(d, paired, task, agentHeader, opt.PrincipalHeader))
		st.Records++
		if paired != nil {
			st.Paired++
		}
		if task != "" {
			st.Correlated++
		}
	}
	return out, st, nil
}

// record is one decision as a federated.decision record: everything in it is Hub's claim.
func record(d Decision, a *Access, task, agentHeader, principalHeader string) client.RecordRequest {
	ev := client.ProviderEvent{Coverage: client.String(CoverageObserved)}
	if task != "" {
		ev.TaskID, ev.Coverage = client.String(task), client.String(CoverageAttributed)
	}
	verdict, result := d.Decision, d.Message
	if d.Decision == "bypass" {
		// A policy with strategy: bypass let the call through without asking the PDP.
		verdict, result = "allow", "bypass"
		if d.Message != "" {
			result += ": " + d.Message
		}
	}
	if result = clean(result); result == "" {
		result = d.Decision
	}
	ev.Decision, ev.Result = client.String(verdict), client.String(result)
	switch {
	case d.Reason != "":
		ev.Reason = client.String(clean(d.Reason))
	case d.Error != "":
		ev.Reason = client.String(clean("error: " + d.Error))
	}
	source := map[string]any{"system": "traefik-hub", "middleware": clean(d.MiddlewareName),
		"middleware_type": d.MiddlewareType, "hub_decision": d.Decision}
	put := func(k, v string) {
		if v = clean(v); v != "" {
			source[k] = v
		}
	}
	put("policy", d.Policy)
	put("trace_id", d.TraceID)
	put("gateway_id", d.GatewayID)
	put("decision_log_id", d.TransparencyLogID)
	put("time", d.Time)
	digests := map[string]any{"decisionLine": d.LineSHA256}
	name := clean(d.MiddlewareName)
	if a != nil {
		target := clean(a.RequestHost + a.RequestPath)
		if target != "" {
			ev.Target = client.String(target)
			name = target
		}
		if u := clean(a.ClientUsername); u != "" && u != "-" {
			ev.Principal = client.String(u)
		} else if principalHeader != "" {
			if u := clean(a.Header(principalHeader)); u != "" {
				ev.Principal = client.String(u)
			}
		}
		if agentHeader != "-" {
			if ag := clean(a.Header(agentHeader)); ag != "" {
				ev.Agent = client.String(ag)
			}
		}
		put("access_log_id", a.TransparencyLogID)
		put("method", a.RequestMethod)
		put("router", a.RouterName)
		if a.DownstreamStatus != nil {
			source["downstream_status"] = *a.DownstreamStatus
		}
		digests["accessLine"] = a.LineSHA256
	}
	if name == "" {
		name = ProviderName
	}
	ev.Subject = map[string]any{"kind": "tool-call", "name": name, "digests": digests}
	ev.Source = source
	return client.RecordRequest{Provider: ProviderName, Kind: Kind, Record: ev}
}

// maxText is what the adapter keeps of one string (the core caps each at 4 KiB, the subject name at 1 KiB).
const maxText = 1024

// clean keeps a string the core will take: valid UTF-8, no NUL or control characters, at most maxText bytes.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxText {
		s = s[:maxText]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}
