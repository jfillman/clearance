package packet

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
)

// exceptionsSection builds one row per exception, in classes. Gate records (deploy.exception, deploy.degraded,
// break-glass, deploy.revoke) and observations seen and not cleared both land here. The empty-list sentence is
// decided last, and only the coverage statement's WindowVerified lets it print.
func (b *builder) exceptionsSection(pk *Packet) {
	var rows []Exception
	bgClose := map[string]Record{} // break-glass id -> its close record
	for _, r := range b.c.records {
		if str(r, "tool") == gate.ToolBreakglassClose {
			bgClose[str(obj(r, "breakglass"), "id")] = r
		}
	}
	laterClear := func(change string, after int64) string {
		for _, r := range b.c.records[after+1:] {
			if str(r, "tool") == "deploy.clear" && changeKey(r) == change && str(obj(r, "change"), "id") != "" {
				b.extra[seqOf(r)] = true
				return fmt.Sprintf("re-cleared at seq %d", seqOf(r))
			}
		}
		return ""
	}
	for _, r := range b.sel {
		tool, seq := str(r, "tool"), seqOf(r)
		cluster, env := place(r)
		subj := strings.Trim(str(r, "app")+" "+env, " ")
		_ = cluster
		switch tool {
		case gate.KindException:
			x := obj(r, "exception")
			kind := str(x, "kind")
			row := Exception{Seq: seq, TS: b.ts(r), Kind: kind, Source: "gate", Subject: subj, Actor: str(x, "actor"),
				Coverage: str(r, "coverage"), Detail: short(x["detail"], 200), OperationalClass: opClass(r)}
			row.Diff = exceptionDiff(x)
			switch kind {
			case gate.KindAttemptedRefused:
				row.Class = ClassRefused
			case gate.KindMonitoringProtection:
				row.Class = ClassMonitoring
			default:
				row.Class = ClassOutOfBand
			}
			row.Window = str(obj(r, "breakglass"), "id")
			switch {
			case row.Window != "":
				row.Resolution = "inside break-glass window " + row.Window
			case laterClear(changeKey(r), seq) != "":
				row.Resolution = laterClear(changeKey(r), seq)
			default:
				row.Resolution = "none recorded"
			}
			rows = append(rows, row)
		case gate.KindDegraded:
			o := obj(r, "outage")
			pol := obj(r, "outage_policy")
			res := "held (the provider denied the change while the core was unreachable)"
			if str(r, "decision") == "allow" {
				res = fmt.Sprintf("auto-cleared under the outage policy (action %s, conforms %v)", str(pol, "action"), pol["conforms"])
			}
			rows = append(rows, Exception{Class: ClassDegraded, Seq: seq, TS: b.ts(r), Kind: "deploy.degraded", Source: "gate", Subject: subj,
				Diff: fmt.Sprintf("core unreachable %s to %s", str(o, "from"), str(o, "to")), Resolution: res, Coverage: str(r, "coverage"), OperationalClass: opClass(r)})
		case gate.ToolBreakglassOpen:
			bg := obj(r, "breakglass")
			id := str(bg, "id")
			res := "open at the end of the window, not yet reconciled"
			detail := short(r["reason"], 200)
			if cl, ok := bgClose[id]; ok {
				res = fmt.Sprintf("closed (%s) at seq %d: %v changes reported in the window", str(obj(cl, "breakglass"), "closed_by"), seqOf(cl), cl["reported"])
			}
			rows = append(rows, Exception{Class: ClassBreakGlass, Seq: seq, TS: b.ts(r), Kind: "window", Source: "gate", Subject: str(r, "target"),
				Actor: str(r, "principal"), Diff: "until " + str(bg, "expires_at"), Resolution: res, Detail: detail, Window: id, Coverage: str(r, "coverage"), OperationalClass: opClass(r)})
		case "deploy.revoke":
			rows = append(rows, Exception{Class: ClassTokens, Seq: seq, TS: b.ts(r), Kind: "token-revoked", Source: "gate", Subject: changeKey(r),
				Detail: short(r["result"], 200), Resolution: orDefault(laterClear(changeKey(r), seq), "token revoked; no later clearance in the window"), OperationalClass: opClass(r)})
		default:
			if str(r, "coverage") == coverageUnavailable && !isObserved(tool) && tool != gate.KindDegraded && tool != gate.KindException {
				rows = append(rows, Exception{Class: ClassDegraded, Seq: seq, TS: b.ts(r), Kind: "outage-read", Source: "runtime", Subject: str(r, "tool"),
					Actor: str(r, "principal"), Diff: str(r, "target"), Resolution: "a read the provider ran while the core was unreachable, posted on recovery",
					Coverage: str(r, "coverage")})
			}
			if tool == "federated.decision" {
				if src := obj(r, "source"); src != nil {
					if c, ok := src["correlated"].(bool); ok && !c {
						rows = append(rows, Exception{Class: ClassCorrelation, Seq: seq, TS: b.ts(r), Kind: "federated-uncorrelated", Source: "federated",
							Subject: str(r, "target"), Actor: str(r, "principal"), Resolution: "none recorded",
							Detail: "another gateway's decision could not be tied to a task", Coverage: str(r, "coverage")})
					}
				}
			}
		}
	}
	rows = append(rows, b.observationRows()...)
	sort.SliceStable(rows, func(i, j int) bool {
		ci, cj := classIndex(rows[i].Class), classIndex(rows[j].Class)
		if ci != cj {
			return ci < cj
		}
		return rows[i].Seq < rows[j].Seq
	})
	ex := Exceptions{Rows: rows, Count: len(rows)}
	if ex.Rows == nil {
		ex.Rows = []Exception{}
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Class]++
	}
	for _, c := range ExceptionClasses {
		ex.ByClass = append(ex.ByClass, Count{c, counts[c]})
	}
	switch {
	case len(rows) > 0:
		ex.Unverified = ""
	case pk.Coverage.WindowVerified:
		ex.Clean = "No exceptions detected in this window, and every observation feed was healthy for the whole of it."
	default:
		ex.Unverified = "This list is empty, but it is not a clean one: " + pk.Coverage.Text +
			" An exception that happened while a feed was blind would not appear here."
	}
	pk.Exceptions = ex
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func classIndex(c string) int {
	for i, x := range ExceptionClasses {
		if x == c {
			return i
		}
	}
	return len(ExceptionClasses)
}

func exceptionDiff(x map[string]any) string {
	var parts []string
	if v := x["expected"]; v != nil {
		parts = append(parts, "expected "+short(v, 80))
	}
	if v := x["observed"]; v != nil {
		parts = append(parts, "observed "+short(v, 80))
	}
	if l, ok := x["objects"].([]any); ok && len(l) > 0 {
		var names []string
		for _, o := range l {
			m, _ := o.(map[string]any)
			names = append(names, strings.Trim(str(m, "kind")+"/"+str(m, "namespace")+"/"+str(m, "name"), "/"))
		}
		parts = append(parts, fmt.Sprintf("%d objects: %s", len(l), cut(strings.Join(names, ", "), 120)))
	}
	if l, ok := x["addresses"].([]any); ok && len(l) > 0 {
		parts = append(parts, fmt.Sprintf("%d addresses: %s", len(l), short(l, 120)))
	}
	if st := obj(x, "state"); st != nil {
		parts = append(parts, "state "+short(st, 80))
	}
	return strings.Join(parts, "; ")
}

// observationRows are the observations seen and not cleared in the window and scope, and the observations whose
// correlation did not clear them.
func (b *builder) observationRows() []Exception {
	var rows []Exception
	for _, r := range b.sel {
		if str(r, "tool") != evidence.KindObservation {
			continue
		}
		seq := seqOf(r)
		cov := "unassessed"
		if a, ok := b.assessed[seq]; ok {
			cov = str(a, "coverage")
		}
		monitoring := false
		if t, ok := num(r["tier"]); ok && t == 3 && verifiedField(r, "tier") {
			monitoring = true
		}
		if cov == evidence.CoverageAuthorizedAndVerified && !monitoring {
			continue
		}
		ac, rs, act := obj(r, "action"), obj(r, "resource"), obj(r, "actor")
		res := str(rs, "kind")
		if n := orDefault(str(rs, "name"), str(rs, "id")); n != "" {
			res += "/" + n
		}
		row := Exception{Seq: seq, TS: b.ts(r), Source: "observation", Scope: str(r, "scope"), Subject: res, Actor: str(act, "subject"),
			Kind: cov, Coverage: cov, OperationalClass: opClass(r)}
		row.Diff = strings.TrimSpace(str(ac, "api") + " " + short(r["state_change"], 160))
		if ok, has := ac["succeeded"].(bool); has && !ok {
			row.Detail = "the operation did not succeed: " + str(ac, "refused_reason")
		}
		switch {
		case monitoring:
			row.Class = ClassMonitoring
		case cov == evidence.CoverageBreakGlass:
			row.Class = ClassBreakGlass
		case cov == evidence.CoverageAttemptedRefused:
			row.Class = ClassRefused
		default:
			row.Class = ClassOutOfBand
		}
		row.Resolution = "none recorded"
		if rr, ok := b.resolved[seq]; ok {
			s := obj(rr, "resolution")
			row.Resolution = str(s, "state")
			row.Cause = str(s, "cause")
		}
		rows = append(rows, row)
		// A provider that named what an operation belongs to (a grant, a plan, a task, a run) and still left it
		// uncleared failed to correlate it: the claim did not hold.
		if c := obj(r, "correlation"); len(c) > 0 && cov != evidence.CoverageAuthorizedAndVerified {
			cr := row
			cr.Class, cr.Kind = ClassCorrelation, "correlation-not-corroborated"
			cr.Detail = "correlation claimed " + short(c, 160) + ", the assessment is " + cov
			rows = append(rows, cr)
		}
	}
	return rows
}

var _ = observe.Healthy

const coverageUnavailable = "coverage-unavailable"
