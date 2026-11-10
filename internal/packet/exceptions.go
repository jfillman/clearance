package packet

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

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
		switch tool {
		case gate.KindException:
			x := obj(r, "exception")
			kind := str(x, "kind")
			row := Exception{Seq: seq, TS: b.ts(r), Kind: kind, Source: "gate", Subject: subj, Actor: str(x, "actor"),
				Coverage: str(r, "coverage"), Detail: short(x["detail"], 200), OperationalClass: opClass(r)}
			row.Diff = exceptionDiff(x)
			if l, ok := x["objects"].([]any); ok {
				for _, o := range l {
					m, _ := o.(map[string]any)
					if k, n := str(m, "kind"), str(m, "name"); k != "" && n != "" && cluster != "" {
						row.keys = append(row.keys, observe.KubeObjectKey(cluster, k, str(m, "namespace"), n))
					}
				}
			}
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
			// A person's resolution (POST /v1/observations/{seq}/resolution) of this exception is the row's resolution,
			// read as an observation row's is: the newest record about the seq wins, with its cause and who set it. It
			// takes precedence over "none recorded" and over a later re-clear; a break-glass window still shows in
			// row.Window.
			if rr, ok := b.resolved[seq]; ok && (row.Class == ClassOutOfBand) {
				s := obj(rr, "resolution")
				row.Resolution = str(s, "state")
				row.Cause = str(s, "cause")
				row.ResolutionSeq = ptr(seqOf(rr))
				row.ResolvedBy = orDefault(str(s, "by"), str(obj(rr, "provider"), "name"))
				b.extra[seqOf(rr)] = true
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
	rows = foldSameChange(append(rows, b.observationRows()...))
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
	ex.Filtered = append(ex.Filtered, b.p.Filtered...)
	sort.SliceStable(ex.Filtered, func(i, j int) bool {
		if ex.Filtered[i].Count != ex.Filtered[j].Count {
			return ex.Filtered[i].Count > ex.Filtered[j].Count
		}
		return ex.Filtered[i].Rule < ex.Filtered[j].Rule
	})
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
		row.key = observe.KubeObjectKey(str(r, "scope"), str(rs, "kind"), str(rs, "namespace"), orDefault(str(rs, "name"), str(rs, "id")))
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
			row.ResolutionSeq = ptr(seqOf(rr))
			row.ResolvedBy = orDefault(str(s, "by"), str(obj(rr, "provider"), "name"))
		}
		if selfVerified(r) {
			row.SourceVerified, row.VerifiedBy = true, "self"
		} else if _, ok := b.verified[seq]; ok {
			row.SourceVerified, row.VerifiedBy = true, "later"
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

// sameChangeWindow is how far apart a gate exception and an observation of the same object may be and still be one
// change: the Argo CD agent scans every minute and an audit collector's queue can trail, so a quarter of an hour.
const sameChangeWindow = 15 * time.Minute

// foldSameChange makes a gate exception (the Argo CD agent's deploy.exception, which names objects) and an
// observation of the same object (the audit collector's, which names who and what changed) one row: the
// observation's, with the gate record's seq in AlsoSeq and its detail appended. Both orders of arrival fold the same,
// since this reads the finished chain. A gate exception that names several objects is folded away only when every one
// of them has an observation; otherwise it stays, and says which were seen by the collector too. Only out-of-band
// rows fold: a refusal, a monitoring operation and a break-glass window are never merged into another row.
func foldSameChange(rows []Exception) []Exception {
	at := func(r Exception) time.Time { t, _ := time.Parse(time.RFC3339, r.TS); return t }
	drop := map[int]bool{}
	for gi, g := range rows {
		if g.Source != "gate" || g.Class != ClassOutOfBand || len(g.keys) == 0 {
			continue
		}
		matched := map[string]bool{}
		for oi, o := range rows {
			if o.Source != "observation" || o.Class != ClassOutOfBand || o.key == "" || !slices.Contains(g.keys, o.key) {
				continue
			}
			d := at(g).Sub(at(o))
			if d < 0 {
				d = -d
			}
			if d > sameChangeWindow {
				continue
			}
			matched[o.key] = true
			rows[oi].AlsoSeq = append(rows[oi].AlsoSeq, g.Seq)
			note := fmt.Sprintf("also reported by the gate's agent (seq %d)", g.Seq)
			if g.Detail != "" {
				note += ": " + g.Detail
			}
			rows[oi].Detail = strings.TrimSpace(rows[oi].Detail + " " + note)
		}
		if len(matched) == len(g.keys) {
			drop[gi] = true
		} else if len(matched) > 0 {
			rows[gi].Detail = strings.TrimSpace(rows[gi].Detail + fmt.Sprintf(" (%d of its %d objects were also observed by the audit collector)", len(matched), len(g.keys)))
		}
	}
	if len(drop) == 0 {
		return rows
	}
	out := rows[:0:0]
	for i, r := range rows {
		if !drop[i] {
			out = append(out, r)
		}
	}
	return out
}

const coverageUnavailable = "coverage-unavailable"

// selfVerified: the observation's own integrity says its source was verified unaltered.
func selfVerified(r Record) bool {
	v, _ := obj(r, "integrity")["sourceVerified"].(bool)
	return v
}

// observedSection is the freeze and incident views' observed changes: every observation in the window and scopes, in
// time order, with how each was assessed and resolved and whether its source was verified. The packet view leaves it
// out (its exceptions section lists what was not cleared).
func (b *builder) observedSection(pk *Packet) {
	if b.p.View != ViewFreeze && b.p.View != ViewIncident {
		return
	}
	oc := &ObservedChanges{Rows: []ObservedChange{}}
	for _, r := range b.sel {
		if str(r, "tool") != evidence.KindObservation {
			continue
		}
		oc.Count++
		if len(oc.Rows) >= MaxObservedChanges {
			oc.Truncated = true
			continue
		}
		seq := seqOf(r)
		ac, rs, act := obj(r, "action"), obj(r, "resource"), obj(r, "actor")
		res := str(rs, "kind")
		if n := orDefault(str(rs, "name"), str(rs, "id")); n != "" {
			res += "/" + n
		}
		row := ObservedChange{Seq: seq, TS: b.ts(r), Scope: str(r, "scope"), Source: str(obj(r, "source"), "name"), Resource: res,
			Actor: str(act, "subject"), API: str(ac, "api"), Coverage: "unassessed", Resolution: "none recorded",
			Diff: short(r["state_change"], 160)}
		if ok, has := ac["succeeded"].(bool); has {
			row.Succeeded = &ok
		}
		if a, ok := b.assessed[seq]; ok {
			row.Coverage = str(a, "coverage")
		}
		if rr, ok := b.resolved[seq]; ok {
			s := obj(rr, "resolution")
			row.Resolution, row.Cause = str(s, "state"), str(s, "cause")
			row.ResolvedBy = orDefault(str(s, "by"), str(obj(rr, "provider"), "name"))
		}
		if selfVerified(r) {
			row.SourceVerified, row.VerifiedBy = true, "self"
		} else if _, ok := b.verified[seq]; ok {
			row.SourceVerified, row.VerifiedBy = true, "later"
		}
		oc.Rows = append(oc.Rows, row)
	}
	pk.Observed = oc
}
