package pipeline

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/vocab"
)

// The revert memory: an apply and its undo are matched across passes (Flush calls), by event time, and one undo can put
// back several changes. The scenario is the one seen live, with documentation values.

var memT0 = time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC)

func rule(port int) map[string]any {
	return map[string]any{"toPort": port, "fromPort": port, "ipRanges": []any{"10.0.0.0/8"}, "ipProtocol": "tcp",
		"ipv4Ranges": []any{map[string]any{"cidrIp": "10.0.0.0/8"}}, "ipv6Ranges": []any{}, "prefixListIds": []any{}, "userIdGroupPairs": []any{}}
}

const ipp = "Configuration.IpPermissions."

func addDelta(ptr string, port int) *Delta {
	return &Delta{Before: map[string]any{ipp + ptr: nil}, After: map[string]any{ipp + ptr: rule(port)}}
}

// awsRaw is a CloudTrail record of a console user's write to a security group.
func awsRaw(id, name string, at time.Time, group string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"eventID":%q,"eventName":%q,"eventSource":"ec2.amazonaws.com","eventTime":%q,
"awsRegion":"us-east-1","recipientAccountId":"111122223333","userAgent":"console.amazonaws.com",
"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/dana"},
"requestParameters":{"groupId":%q}}`, id, name, at.Format(time.RFC3339), group))
}

type memRig struct {
	t *testing.T
	p *Pipeline
}

func newMemRig(t *testing.T) *memRig {
	return &memRig{t: t, p: New(mustRules(t), nil, vocab.Default())}
}

func (r *memRig) put(id, name string, off time.Duration, group string, d *Delta) *Assessment {
	r.t.Helper()
	a, disp, _, err := r.p.Process(RawEvent{Provider: AWS, Scope: "111122223333", Raw: awsRaw(id, name, memT0.Add(off), group), Delta: d, Final: true})
	if err != nil || disp != Assessed {
		r.t.Fatalf("%s: %v %v", id, disp, err)
	}
	return a
}

func (r *memRig) pass() []Exception { _, ex := r.p.Flush(); return ex }

func reverted(exs []Exception) []Exception {
	var out []Exception
	for _, x := range exs {
		if x.Reverted {
			out = append(out, x)
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func revokeBoth() *Delta {
	return &Delta{Before: map[string]any{ipp + "0": rule(8443), ipp + "1": rule(9443)}, After: map[string]any{ipp + "0": nil, ipp + "1": nil}}
}

func TestRevertMemoryLiveScenario(t *testing.T) {
	r := newMemRig(t)
	sg := "sg-0123456789abcdef0"
	// pass 1: add A (event 04:43:20) is emitted first
	r.put("evt-add-9443", "AuthorizeSecurityGroupIngress", 43*time.Minute+20*time.Second, sg, addDelta("0", 9443))
	if x := r.pass(); len(x) != 1 || x[0].Reverted {
		t.Fatalf("pass 1: %+v", x)
	}
	// pass 2 (after a restart): add B (event 04:24:53), earlier by event time than A
	r.put("evt-add-8443", "AuthorizeSecurityGroupIngress", 24*time.Minute+53*time.Second, sg, addDelta("0", 8443))
	if x := r.pass(); len(x) != 1 || x[0].Reverted {
		t.Fatalf("pass 2: %+v", x)
	}
	// pass 3: one revoke of both (05:11:45), 47 and 28 minutes later
	r.put("evt-revoke", "RevokeSecurityGroupIngress", 71*time.Minute+45*time.Second, sg, revokeBoth())
	rev := reverted(r.pass())
	if len(rev) != 1 {
		t.Fatalf("one reverted exception: %+v", rev)
	}
	x := rev[0]
	if x.Resolution != "reverted" || !sameSet(x.Events, []string{"evt-add-9443", "evt-add-8443", "evt-revoke"}) {
		t.Fatalf("it folds all three events: %+v", x)
	}
	if x.Events[0] != "evt-add-8443" || x.Events[2] != "evt-revoke" {
		t.Fatalf("by event time, the undo last: %v", x.Events)
	}
	// the collector posts `reverted` for every id in Events (resolve): so all three seqs
	seqs := map[string]int64{"evt-add-9443": 1, "evt-add-8443": 2, "evt-revoke": 3}
	posted := 0
	for _, id := range x.Events {
		if _, ok := seqs[id]; ok {
			posted++
		}
	}
	if posted != 3 {
		t.Fatalf("a reverted resolution for each of three seqs: %d", posted)
	}
	// nothing is left in the memory: a later identical add is a fresh, still-live exception
	if n := len(r.p.corr.mem); n != 0 {
		t.Fatalf("folded changes leave the memory: %d", n)
	}
}

func TestRevertMemorySingleAddThenRemoveAcrossPasses(t *testing.T) {
	r := newMemRig(t)
	sg := "sg-0123456789abcdef0"
	r.put("a", "AuthorizeSecurityGroupIngress", 0, sg, addDelta("0", 9443))
	r.pass()
	r.put("b", "RevokeSecurityGroupIngress", 40*time.Minute, sg,
		&Delta{Before: map[string]any{ipp + "3": rule(9443)}, After: map[string]any{ipp + "3": nil}}) // a different position
	rev := reverted(r.pass())
	if len(rev) != 1 || !sameSet(rev[0].Events, []string{"a", "b"}) {
		t.Fatalf("%+v", rev)
	}
}

func TestRevertMemoryUndoOutsideWindowDoesNotFold(t *testing.T) {
	r := newMemRig(t)
	sg := "sg-0123456789abcdef0"
	r.put("a", "AuthorizeSecurityGroupIngress", 0, sg, addDelta("0", 9443))
	r.pass()
	r.put("b", "RevokeSecurityGroupIngress", 61*time.Minute, sg,
		&Delta{Before: map[string]any{ipp + "0": rule(9443)}, After: map[string]any{ipp + "0": nil}})
	exs := r.pass()
	if len(reverted(exs)) != 0 || len(exs) != 1 {
		t.Fatalf("an undo after the window is its own exception: %+v", exs)
	}
}

func TestRevertMemoryPartialUndoFoldsOnlyTheMatchingOne(t *testing.T) {
	r := newMemRig(t)
	sg := "sg-0123456789abcdef0"
	r.put("a8443", "AuthorizeSecurityGroupIngress", 0, sg, addDelta("0", 8443))
	r.pass()
	r.put("a9443", "AuthorizeSecurityGroupIngress", 10*time.Minute, sg, addDelta("0", 9443))
	r.pass()
	// removes only the 9443 rule: the most recent change is what it undoes, at k=1; the run of both does not match
	r.put("rv2", "RevokeSecurityGroupIngress", 30*time.Minute, sg,
		&Delta{Before: map[string]any{ipp + "0": rule(9443)}, After: map[string]any{ipp + "0": nil}})
	rev := reverted(r.pass())
	if len(rev) != 1 || !sameSet(rev[0].Events, []string{"a9443", "rv2"}) {
		t.Fatalf("folds only the matching one: %+v", rev)
	}
	// the other (8443) stays remembered, still live
	if n := len(r.p.corr.mem); n != 1 {
		t.Fatalf("one change still remembered: %d", n)
	}
}

func TestRevertMemoryEmptyDiffsNeverFold(t *testing.T) {
	r := newMemRig(t)
	sg := "sg-0123456789abcdef0"
	empty := func() *Delta { return &Delta{Before: map[string]any{}, After: map[string]any{}} }
	nulls := func() *Delta { return &Delta{Before: map[string]any{"x": nil}, After: map[string]any{"x": nil}} }
	r.put("a", "ModifySecurityGroupRules", 0, sg, empty())
	r.pass()
	r.put("b", "ModifySecurityGroupRules", time.Minute, sg, nulls())
	r.put("c", "ModifySecurityGroupRules", 2*time.Minute, sg, nil) // no diff at all
	if rev := reverted(r.pass()); len(rev) != 0 {
		t.Fatalf("an empty diff is never an undo: %+v", rev)
	}
}

func TestRevertMemoryMonitoringIsNeverFolded(t *testing.T) {
	r := newMemRig(t)
	// StopLogging is a monitoring operation: it is never folded away, whatever follows
	a := r.put("stop", "StopLogging", 0, "trail-1", &Delta{Before: map[string]any{"IsLogging": true}, After: map[string]any{"IsLogging": false}})
	if a.Outcome != OutcomeMonitoring {
		t.Fatalf("expected a monitoring outcome: %s", a.Outcome)
	}
	r.pass()
	r.put("start", "StartLogging", 5*time.Minute, "trail-1", &Delta{Before: map[string]any{"IsLogging": false}, After: map[string]any{"IsLogging": true}})
	exs := r.pass()
	if len(reverted(exs)) != 0 {
		t.Fatalf("a monitoring operation is not folded: %+v", exs)
	}
	for _, c := range r.p.corr.mem {
		for _, m := range c {
			if m.Outcome == OutcomeMonitoring {
				t.Fatalf("monitoring is not remembered as revertible")
			}
		}
	}
}

func TestRevertMemoryIsBounded(t *testing.T) {
	r := newMemRig(t)
	sg := "sg-0123456789abcdef0"
	for i := 0; i < maxMemoryPerResource+30; i++ {
		r.put(fmt.Sprintf("e%03d", i), "AuthorizeSecurityGroupIngress", time.Duration(i)*time.Second, sg, addDelta("0", 1000+i))
		r.pass()
	}
	key := "111122223333|" + mustKey(t, r)
	if n := len(r.p.corr.mem[key]); n != maxMemoryPerResource {
		t.Fatalf("per resource: %d, want %d", n, maxMemoryPerResource)
	}
	if r.p.corr.mem[key][0].EventID != "e030" {
		t.Fatalf("the oldest go first: %s", r.p.corr.mem[key][0].EventID)
	}
	// in total
	c := newCorrelator(mustRules(t))
	for i := 0; i < maxMemoryTotal+500; i++ {
		c.Add(memAssess(fmt.Sprintf("x%d", i), fmt.Sprintf("res-%d", i), memT0.Add(time.Duration(i)*time.Millisecond)))
		if i%100 == 99 {
			c.Flush()
		}
	}
	c.Flush()
	n := 0
	for _, l := range c.mem {
		n += len(l)
	}
	if n > maxMemoryTotal {
		t.Fatalf("total memory %d exceeds %d", n, maxMemoryTotal)
	}
	// and expires by window: an event two hours later forgets everything older
	c.Add(memAssess("late", "res-late", memT0.Add(3*time.Hour)))
	c.Flush()
	n = 0
	for _, l := range c.mem {
		n += len(l)
	}
	if n != 1 {
		t.Fatalf("expired by window: %d", n)
	}
}

func mustKey(t *testing.T, r *memRig) string {
	for k := range r.p.corr.mem {
		return k[len("111122223333|"):]
	}
	t.Fatal("empty memory")
	return ""
}

func memAssess(id, res string, at time.Time) *Assessment {
	return &Assessment{EventID: id, Scope: "s", Time: at, Resource: res, Succeeded: true, Actor: "u", Outcome: OutcomeOutOfBand,
		Coverage: "out-of-band-detected", Tier: 2, Severity: "high", Signal: "x", ev: &Event{Subject: "u", ExecKey: "session:" + id}}
}

func TestValueDeltaIgnoresNamesAndNulls(t *testing.T) {
	add, rem := valueDelta(map[string]any{"a.0": nil, "a.1": "x", "b": 1}, map[string]any{"a.0": "x", "a.1": nil, "b": 1})
	if len(add) != 0 || len(rem) != 0 {
		t.Fatalf("a value that moved is no change: %v %v", add, rem)
	}
	add, rem = valueDelta(map[string]any{"a": map[string]any{"z": 1, "y": 2}}, map[string]any{"a": map[string]any{"y": 2, "z": 1}, "b": "n"})
	if len(add) != 1 || add[0] != `"n"` || len(rem) != 0 {
		t.Fatalf("%v %v", add, rem)
	}
}
