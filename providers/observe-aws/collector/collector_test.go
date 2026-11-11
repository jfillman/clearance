package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/providers/observe-aws/detect"
	"github.com/jfillman/clearance/providers/observe-aws/scope"
)

// fakeCore is the core's contract for an observed provider: a record per post, an observation de-duplicated by
// source.event_id (the answer is the first record's seq and Duplicate).
type fakeCore struct {
	reqs      []*client.RecordRequest
	byEvent   map[string]int64
	fail      error
	failKind  string
	failTimes int
}

func (f *fakeCore) Record(_ context.Context, r *client.RecordRequest) (*client.RecordRef, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	if f.byEvent == nil {
		f.byEvent = map[string]int64{}
	}
	if id, ok := r.Record.Source["event_id"].(string); ok && id != "" {
		key := r.Kind + "\x00" + id
		if seq, dup := f.byEvent[key]; dup {
			return &client.RecordRef{Seq: seq, Duplicate: true}, nil
		}
		if f.failKind == r.Kind && f.failTimes > 0 {
			f.failTimes--
			return nil, errors.New("transient")
		}
		f.reqs = append(f.reqs, r)
		f.byEvent[key] = int64(len(f.reqs))
		return &client.RecordRef{Seq: int64(len(f.reqs))}, nil
	}
	f.reqs = append(f.reqs, r)
	return &client.RecordRef{Seq: int64(len(f.reqs))}, nil
}

func (f *fakeCore) kinds() []string {
	var k []string
	for _, r := range f.reqs {
		k = append(k, r.Kind)
	}
	return k
}

func (f *fakeCore) of(kind string) []*client.RecordRequest {
	var out []*client.RecordRequest
	for _, r := range f.reqs {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

type fakeApplies []detect.Apply

func (f fakeApplies) Applies(context.Context, time.Time) ([]detect.Apply, error) { return f, nil }

type rig struct {
	t    *testing.T
	clk  *clock
	c    *Collector
	co   *fakeCore
	acks int
}

func newRig(t *testing.T, applies ...detect.Apply) *rig {
	t.Helper()
	rs, err := pipeline.Default()
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t0.Add(time.Hour)}
	lk := &EvidenceLookups{Src: fakeApplies(applies), ScopeEnv: map[string]string{acct: "lab"}, Now: clk.now}
	co := &fakeCore{}
	c := &Collector{Cfg: Config{Accounts: []string{acct}, Version: "test"}, Pipe: pipeline.New(rs, lk, vocab.Vocabulary{}),
		Filter: &scope.Filter{DataBuckets: []string{"tf-state"}}, Rec: &Reconciler{Settle: 5 * time.Minute, Now: clk.now},
		Core: co, Lookups: lk, Now: clk.now}
	return &rig{t: t, clk: clk, c: c, co: co}
}

func (r *rig) ingest(body []byte, at time.Time) {
	r.t.Helper()
	it := mustItem(body, at)
	it.Acks = []func(){func() { r.acks++ }}
	if err := r.c.Ingest(it); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) settle() {
	r.t.Helper()
	r.clk.add(10 * time.Minute)
	if err := r.c.Step(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

// The first Done-when: a console security-group change appears with its actor (sourceIdentity), the Config diff and a
// resolution; and it is one exception though two feeds reported it.
func TestConsoleChangeIsAnExceptionWithActorDiffAndResolution(t *testing.T) {
	r := newRig(t)
	r.ingest(consoleSG("ev-console", t0).envelope(), t0)
	r.ingest(sgConfig(t0.Add(30*time.Second), "ev-console").envelope(), t0)
	r.settle()
	if got := strings.Join(r.co.kinds(), ","); got != "observation,assessment,resolution" {
		t.Fatalf("one change is one observation, one assessment, one resolution: %s", got)
	}
	o := r.co.of("observation")[0].Record
	if o.Actor["subject"] != "dana@example.com" || o.Actor["issuer"] != ssoRole {
		t.Fatalf("the actor is the quoted sourceIdentity under the SSO role: %v", o.Actor)
	}
	if o.Resource["kind"] != "ec2" || o.Resource["id"] != "sg-0abc1234" {
		t.Fatalf("%v", o.Resource)
	}
	after, _ := o.StateChange["after"].(map[string]any)
	if after["Configuration.IpPermissions.0"] == nil {
		t.Fatalf("the Config diff is the state change: %v", o.StateChange)
	}
	if o.Integrity["sourceVerified"] != false || o.Integrity["method"] != MethodEventBridge || o.Integrity["completenessClaimed"] != true {
		t.Fatalf("an EventBridge delivery is not signed: %v", o.Integrity)
	}
	as := r.co.of("assessment")[0].Record
	if *as.Coverage != "out-of-band-detected" || *as.Tier != 2 {
		t.Fatalf("%s tier %d", *as.Coverage, *as.Tier)
	}
	d := str(as.Attribution["detail"])
	if !strings.Contains(d, "Configuration.IpPermissions.0 (CREATE)") || !strings.Contains(d, "dana@example.com") {
		t.Fatalf("the assessment points at the Config diff and the actor: %s", d)
	}
	res := r.co.of("resolution")[0].Record
	if res.Resolution["state"] != "still-live" {
		t.Fatal(res.Resolution)
	}
	if r.acks != 2 {
		t.Fatalf("both deliveries are acked once posted: %d", r.acks)
	}
}

// Either order, with the item first, the result is the same single exception.
func TestConfigFirstIsTheSameOneException(t *testing.T) {
	r := newRig(t)
	r.ingest(sgConfig(t0.Add(30*time.Second), "ev-console").envelope(), t0)
	r.clk.add(2 * time.Minute)
	r.ingest(consoleSG("ev-console", t0).envelope(), t0)
	r.settle()
	if len(r.co.of("observation")) != 1 || len(r.co.of("assessment")) != 1 {
		t.Fatalf("%v", r.co.kinds())
	}
	if r.co.of("observation")[0].Record.StateChange == nil {
		t.Fatal("the diff is attached")
	}
}

// The second: a gated apply is not an exception. The runner's claim is checked against the recorded outcome.
func TestGatedApplyIsCleared(t *testing.T) {
	r := newRig(t, detect.Apply{Change: "clr_apply1", Env: "lab", Digest: "sha256:" + planDigest,
		Started: t0.Add(-time.Minute), Finished: t0.Add(time.Minute)})
	r.ingest(gatedSG("ev-gated", t0).envelope(), t0)
	r.ingest(sgConfig(t0.Add(30*time.Second), "ev-gated").envelope(), t0)
	r.settle()
	if got := strings.Join(r.co.kinds(), ","); got != "observation,assessment" {
		t.Fatalf("a cleared change has no resolution to make: %s", got)
	}
	as := r.co.of("assessment")[0].Record
	if *as.Coverage != "authorized-and-verified" || *as.Tier != 0 || as.Attribution["grant"] != "clr_apply1" {
		t.Fatalf("%s %v", *as.Coverage, as.Attribution)
	}
	o := r.co.of("observation")[0].Record
	if o.Correlation["grant"] != "clr_apply1" || o.Correlation["plan"] != "sha256:"+planDigest || o.Correlation["run_id"] != "77" {
		t.Fatal(o.Correlation)
	}
}

// A claim in the user agent that no recorded apply backs is not a clearance.
func TestUnbackedClaimIsNotCleared(t *testing.T) {
	r := newRig(t) // no applies recorded
	r.ingest(gatedSG("ev-forged", t0).envelope(), t0)
	r.settle()
	as := r.co.of("assessment")[0].Record
	if *as.Coverage == "authorized-and-verified" {
		t.Fatalf("a self-reported user agent must not clear a change: %v", as.Attribution)
	}
}

// StopLogging is a monitoring-protection event, whatever explains it; the core flips the health from the observation.
func TestStopLoggingIsMonitoringProtection(t *testing.T) {
	r := newRig(t)
	e := ct{id: "ev-stop", name: "StopLogging", source: "cloudtrail.amazonaws.com", at: t0, utype: "AssumedRole", issuer: ssoRole,
		arn: "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/dana", srcIdentity: "dana@example.com",
		params: map[string]any{"name": "organization"}}
	r.ingest(e.envelope(), t0)
	r.settle()
	o := r.co.of("observation")[0].Record
	if o.Action["protects_monitoring"] != true || o.Action["succeeded"] != true {
		t.Fatalf("%v", o.Action)
	}
	as := r.co.of("assessment")[0].Record
	if *as.Tier != 3 || !strings.Contains(str(as.Attribution["detail"]), "operation on the controls that watch") {
		t.Fatalf("%d %v", *as.Tier, as.Attribution)
	}
	// refused: still tier 3, and the observation says it did not succeed (the core flips degraded, not blind)
	e.id, e.errCode = "ev-stop-2", "AccessDenied"
	r.ingest(e.envelope(), t0)
	r.settle()
	o = r.co.of("observation")[1].Record
	if o.Action["succeeded"] != false || o.Action["protects_monitoring"] != true || str(o.Action["refused_reason"]) == "" {
		t.Fatalf("%v", o.Action)
	}
}

func TestReadsServiceEventsAndUnevaluatedAreasAreCountedNotPosted(t *testing.T) {
	r := newRig(t)
	ro := true
	read := consoleSG("ev-read", t0)
	read.readOnly = &ro
	svc := consoleSG("ev-svc", t0)
	svc.utype = "AWSService"
	ssm := ct{id: "ev-ssm", name: "StartSession", source: "ssm.amazonaws.com", at: t0, utype: "AssumedRole", issuer: ssoRole, arn: "a"}
	rds := ct{id: "ev-rds", name: "ModifyDBInstance", source: "rds.amazonaws.com", at: t0, utype: "AssumedRole", issuer: ssoRole, arn: "a"}
	otherAcct := consoleSG("ev-other", t0)
	for _, e := range []ct{read, svc, ssm, rds, otherAcct} {
		body := e.envelope()
		if e.id == "ev-other" {
			body = []byte(strings.ReplaceAll(string(body), `"recipientAccountId":"`+acct+`"`, `"recipientAccountId":"999988887777"`))
		}
		r.ingest(body, t0)
	}
	r.settle()
	if len(r.co.reqs) != 0 {
		t.Fatalf("nothing to post: %v", r.co.kinds())
	}
	s := r.c.Stats()
	if s.NotWrites != 2 || s.OutOfAccounts != 1 || s.NotEvaluated["ssm (not classified)"] != 1 || s.NotEvaluated["RDS"] != 1 {
		t.Fatalf("%+v", s)
	}
	if r.acks != 5 {
		t.Fatalf("what is not posted is acked at once: %d", r.acks)
	}
	if st := r.c.Filter.Statement(); !strings.Contains(st, "ssm (not classified) 1") || !strings.Contains(st, "SSM session contents") {
		t.Fatal(st)
	}
}

// At-least-once: a failed post is not acked and is retried; a redelivery is the core's duplicate, never a second record.
func TestAtLeastOnceRelyingOnTheCoresDeduplication(t *testing.T) {
	r := newRig(t)
	r.ingest(consoleSG("ev-1", t0).envelope(), t0)
	r.co.fail = errors.New("core unreachable")
	r.clk.add(10 * time.Minute)
	if err := r.c.Step(context.Background()); err == nil {
		t.Fatal("the failure is reported")
	}
	if r.acks != 0 {
		t.Fatal("a failed post must not delete the queue message")
	}
	r.co.fail = nil
	if err := r.c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.co.of("observation")) != 1 || r.acks != 1 {
		t.Fatalf("%v acks %d", r.co.kinds(), r.acks)
	}
	// The queue delivers it again (visibility timeout): acked, nothing new.
	r.ingest(consoleSG("ev-1", t0).envelope(), t0)
	r.settle()
	if len(r.co.of("observation")) != 1 || r.acks != 2 {
		t.Fatalf("%v acks %d", r.co.kinds(), r.acks)
	}
	// The collector restarted and lost its memory: the core's duplicate answer stops the second chain of records.
	r2 := newRig(t)
	r2.c.Core = r.co
	r2.ingest(consoleSG("ev-1", t0).envelope(), t0)
	r2.settle()
	if len(r.co.of("observation")) != 1 || len(r.co.of("assessment")) != 1 || len(r.co.of("resolution")) != 1 {
		t.Fatalf("a duplicate observation brings no second assessment: %v", r.co.kinds())
	}
	if r2.c.Stats().Duplicates != 1 || r2.acks != 1 {
		t.Fatalf("%+v acks %d", r2.c.Stats(), r2.acks)
	}
}

func TestConfigItemNoEventExplainsIsObservedNotAttributed(t *testing.T) {
	r := newRig(t)
	r.ingest(sgConfig(t0).envelope(), t0)
	r.settle()
	if got := strings.Join(r.co.kinds(), ","); got != "observation,assessment,resolution" {
		t.Fatal(got)
	}
	o, as := r.co.of("observation")[0].Record, r.co.of("assessment")[0].Record
	if !strings.HasPrefix(str(o.Source["event_id"]), "cfg:") || *as.Coverage != "observed-not-attributed" || str(as.Attribution["signal"]) != "config.item-without-event" {
		t.Fatalf("%v %v", o.Source, as)
	}
	if r.c.Stats().ConfigOnly != 1 {
		t.Fatal("counted")
	}
}

func TestRefusedAttemptIsRecordedAsRefused(t *testing.T) {
	r := newRig(t)
	e := consoleSG("ev-refused", t0)
	e.errCode = "UnauthorizedOperation"
	r.ingest(e.envelope(), t0)
	r.settle()
	as := r.co.of("assessment")[0].Record
	if *as.Coverage != "attempted-refused" {
		t.Fatal(*as.Coverage)
	}
}

func TestDataEventsOnlyOnConfiguredBuckets(t *testing.T) {
	r := newRig(t)
	put := func(id, bucket string) ct {
		return ct{id: id, name: "PutObject", source: "s3.amazonaws.com", at: t0, utype: "AssumedRole", issuer: ssoRole,
			arn: "arn:aws:sts::111122223333:assumed-role/x/y", category: "Data", params: map[string]any{"bucketName": bucket, "key": "network/lab/terraform.tfstate"}}
	}
	r.ingest(put("ev-state", "tf-state").envelope(), t0)
	r.ingest(put("ev-else", "random-bucket").envelope(), t0)
	r.settle()
	if n := len(r.co.of("observation")); n != 1 || r.co.of("observation")[0].Record.Source["event_id"] != "ev-state" {
		t.Fatalf("%d", n)
	}
	if r.c.Stats().NotEvaluated["S3 data events of other buckets"] != 1 {
		t.Fatalf("%+v", r.c.Stats())
	}
	if r.co.of("observation")[0].Record.Source["kind"] != "data" {
		t.Fatal("a data event is said to be one")
	}
}

func TestParseMessageRefusesWhatTheRulesDoNotSend(t *testing.T) {
	if _, err := ParseMessage([]byte(`{"detail-type":"EC2 Instance State-change Notification","detail":{}}`), t0); err == nil {
		t.Fatal("an unknown detail-type is an error, not a silent drop")
	}
	if _, err := ParseMessage([]byte(`not json`), t0); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := ParseMessage([]byte(fmt.Sprintf(`{"detail-type":"Config Configuration Item Change","detail":{"configurationItem":{}}}`)), t0); err == nil {
		t.Fatal("a configuration item with no resource is an error")
	}
}

// A failed assessment after a posted observation is completed by the retry: the core ends with one observation, one
// assessment and one resolution (their event ids are derived from the event's, so each post is idempotent).
func TestAssessmentFailureIsCompletedByTheRetry(t *testing.T) {
	r := newRig(t)
	r.co.failKind, r.co.failTimes = "assessment", 1
	r.ingest(consoleSG("ev-1", t0).envelope(), t0)
	r.clk.add(10 * time.Minute)
	if err := r.c.Step(context.Background()); err == nil {
		t.Fatal("the failed assessment is reported")
	}
	if r.acks != 0 || len(r.co.of("observation")) != 1 || len(r.co.of("assessment")) != 0 {
		t.Fatalf("%v acks %d", r.co.kinds(), r.acks)
	}
	if err := r.c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.co.kinds(), ",") != "observation,assessment,resolution" || r.acks != 1 {
		t.Fatalf("%v acks %d", r.co.kinds(), r.acks)
	}
	if got := *r.co.of("assessment")[0].Record.Coverage; got != "out-of-band-detected" {
		t.Fatal(got)
	}
}

// The live gate: Config's item for a console CreateSecurityGroup did not arrive inside the settle window. The event
// posts with its own request as the diff, the created id as the resource id and the name kept.
func TestConsoleCreateWithoutAConfigItemCarriesItsRequestAsTheDiff(t *testing.T) {
	r := newRig(t)
	c := consoleSG("ev-create", t0)
	c.name = "CreateSecurityGroup"
	c.params = map[string]any{"groupName": "test-sg", "groupDescription": "test", "vpcId": "vpc-0abc",
		"password": "hunter2", "tagSpecificationSet": map[string]any{"items": []any{map[string]any{"secretKey": "x", "k": "v"}}}}
	c.response = map[string]any{"requestId": "r-1", "groupId": "sg-0new1234"}
	r.ingest(c.envelope(), t0)
	r.settle()
	o := r.co.of("observation")[0].Record
	if o.Resource["id"] != "sg-0new1234" || o.Resource["name"] != "test-sg" {
		t.Fatalf("the created id is the resource id: %v", o.Resource)
	}
	sc := o.StateChange
	after, _ := sc["after"].(map[string]any)
	if sc["source"] != "cloudtrail-request" || after["groupName"] != "test-sg" || len(sc["before"].(map[string]any)) != 0 {
		t.Fatalf("%v", sc)
	}
	b, _ := json.Marshal(sc)
	if strings.Contains(string(b), "hunter2") || after["password"] != "[redacted]" ||
		after["tagSpecificationSet"].(map[string]any)["items"].([]any)[0].(map[string]any)["secretKey"] != "[redacted]" {
		t.Fatalf("secret-bearing parameters are stripped: %s", b)
	}
	if r.c.Stats().RequestDiffs != 1 {
		t.Fatal("counted")
	}
}

func TestAConfigDiffWinsOverTheRequestAndAnOversizedRequestIsBounded(t *testing.T) {
	r := newRig(t)
	r.ingest(consoleSG("ev-console", t0).envelope(), t0)
	r.ingest(sgConfig(t0.Add(30*time.Second), "ev-console").envelope(), t0)
	r.settle()
	if sc := r.co.of("observation")[0].Record.StateChange; sc["source"] != nil {
		t.Fatalf("a joined Config diff is the diff: %v", sc)
	}
	big := &ctView{Request: map[string]any{"a": strings.Repeat("x", maxStateChange+1), "b": 1}}
	sc := requestDiff(big)
	after := sc["after"].(map[string]any)
	if after["truncated"] == nil || len(after["parameters"].([]string)) != 2 {
		t.Fatalf("%v", after)
	}
	if requestDiff(&ctView{}) != nil {
		t.Fatal("no request, no diff")
	}
}

// A Config item that arrives after its event was posted is counted, and shows in the health detail.
func TestALateConfigItemIsCountedInTheHealthDetail(t *testing.T) {
	r := newRig(t)
	r.ingest(consoleSG("ev-console", t0).envelope(), t0)
	r.settle()
	r.ingest(sgConfig(t0.Add(30*time.Second), "ev-console").envelope(), t0)
	if err := r.c.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.c.Rec.Late() != 1 {
		t.Fatal("late")
	}
	h := &Health{Col: r.c, Cfg: HealthConfig{Account: acct}}
	found := false
	for _, ck := range h.Checks(context.Background()) {
		if ck.name == "config-join" && ck.ok && strings.Contains(ck.detail, "after their event was posted: 1") {
			found = true
		}
	}
	if !found {
		t.Fatal("the health detail counts the late item")
	}
}

// AWS Config's first discovery of resources that already existed is a baseline, not an unexplained change; a resource
// really created without a CloudTrail event stays an exception.
func TestConfigFirstDiscoveryIsBaselineAndACreationWithoutAnEventIsNot(t *testing.T) {
	r := newRig(t)
	disc := sgConfig(t0)
	disc.status, disc.changeType = "ResourceDiscovered", "CREATE"
	disc.created = t0.Add(-72 * time.Hour).Format(time.RFC3339)
	r.ingest(disc.envelope(), t0)
	r.settle()
	if len(r.co.kinds()) != 0 || r.c.Stats().Baseline != 1 || r.acks != 1 {
		t.Fatalf("the discovery is counted and acked, not posted: %v %+v", r.co.kinds(), r.c.Stats())
	}
	made := sgConfig(t0.Add(time.Minute))
	made.resourceID, made.status, made.changeType = "sg-0made5678", "ResourceDiscovered", "CREATE"
	made.created = t0.Add(time.Minute - 20*time.Second).Format(time.RFC3339)
	noTime := sgConfig(t0.Add(2 * time.Minute))
	noTime.resourceID, noTime.status = "sg-0notime", "ResourceDiscovered"
	r.ingest(made.envelope(), t0)
	r.ingest(noTime.envelope(), t0)
	r.settle()
	if got := len(r.co.of("observation")); got != 2 || r.c.Stats().ConfigOnly != 2 || r.c.Stats().Baseline != 1 {
		t.Fatalf("a created resource, and one whose age is unknown, stay exceptions: %d %+v", got, r.c.Stats())
	}
}

func TestCreatedIDIsOnlyTakenFromACreateCallAndPrefersTheCreatedResource(t *testing.T) {
	snap := &ctView{Name: "CreateSnapshot", Response: map[string]any{"volumeId": "vol-0src", "snapshotId": "snap-0new"}}
	if got := createdID(snap); got != "snap-0new" {
		t.Fatal(got)
	}
	attach := &ctView{Name: "AttachVolume", Response: map[string]any{"volumeId": "vol-0a", "instanceId": "i-0b"}}
	if got := createdID(attach); got != "" {
		t.Fatalf("an attach creates nothing: %s", got)
	}
}

// A console user adds two rules to a security group, emitted in different passes and out of event order, then removes both
// with one call in a third pass: every observation of the three gets a `reverted` resolution (the revert memory, and a
// value match that ignores the positional property names).
func TestRevertOfSeveralChangesInLaterPassesIsResolvedForEachObservation(t *testing.T) {
	r := newRig(t)
	rule := func(port int) map[string]any {
		return map[string]any{"fromPort": port, "toPort": port, "ipRanges": []string{"10.0.0.0/8"}}
	}
	cfg := func(at time.Time, event string, before, after map[string]any) cfgItem {
		ch := map[string]map[string]any{}
		for k := range before {
			ch[k] = map[string]any{"previousValue": before[k], "updatedValue": after[k], "changeType": "UPDATE"}
		}
		return cfgItem{resourceID: "sg-0abc1234", name: "web", at: at, related: []string{event}, changed: ch}
	}
	atA, atB, atR := t0.Add(43*time.Minute), t0.Add(24*time.Minute), t0.Add(71*time.Minute)

	r.ingest(consoleSG("ev-add-9443", atA).envelope(), atA)
	r.ingest(cfg(atA.Add(30*time.Second), "ev-add-9443", map[string]any{"Configuration.IpPermissions.0": nil},
		map[string]any{"Configuration.IpPermissions.0": rule(9443)}).envelope(), atA)
	r.settle()
	r.ingest(consoleSG("ev-add-8443", atB).envelope(), atB)
	r.ingest(cfg(atB.Add(30*time.Second), "ev-add-8443", map[string]any{"Configuration.IpPermissions.0": nil},
		map[string]any{"Configuration.IpPermissions.0": rule(8443)}).envelope(), atB)
	r.settle()
	rv := consoleSG("ev-revoke", atR)
	rv.name = "RevokeSecurityGroupIngress"
	r.ingest(rv.envelope(), atR)
	r.ingest(cfg(atR.Add(30*time.Second), "ev-revoke",
		map[string]any{"Configuration.IpPermissions.0": rule(8443), "Configuration.IpPermissions.1": rule(9443)},
		map[string]any{"Configuration.IpPermissions.0": nil, "Configuration.IpPermissions.1": nil}).envelope(), atR)
	r.settle()

	obs := r.co.of("observation")
	if len(obs) != 3 {
		t.Fatalf("three observations: %d", len(obs))
	}
	reverted := map[any]bool{}
	for _, rr := range r.co.of("resolution") {
		if rr.Record.Resolution["state"] == "reverted" {
			reverted[rr.Record.About["seq"]] = true
		}
	}
	if len(reverted) != 3 {
		t.Fatalf("a reverted resolution about each of the three observations: %v", reverted)
	}
}

// Removing a different, pre-existing rule that sits at the same Config pointer is not the undo of an added rule.
func TestRevokeOfAnotherRuleIsNotARevertOfTheAdd(t *testing.T) {
	r := newRig(t)
	rule := func(port int) map[string]any {
		return map[string]any{"fromPort": port, "toPort": port, "ipRanges": []string{"10.0.0.0/8"}}
	}
	cfg := func(at time.Time, event string, before, after any) cfgItem {
		return cfgItem{resourceID: "sg-0abc1234", name: "web", at: at, related: []string{event}, changed: map[string]map[string]any{
			"Configuration.IpPermissions.0": {"previousValue": before, "updatedValue": after, "changeType": "UPDATE"}}}
	}
	atA, atR := t0.Add(5*time.Minute), t0.Add(20*time.Minute)
	r.ingest(consoleSG("ev-add", atA).envelope(), atA)
	r.ingest(cfg(atA.Add(30*time.Second), "ev-add", nil, rule(9443)).envelope(), atA)
	r.settle()
	rv := consoleSG("ev-revoke", atR)
	rv.name = "RevokeSecurityGroupIngress"
	r.ingest(rv.envelope(), atR)
	r.ingest(cfg(atR.Add(30*time.Second), "ev-revoke", rule(22), nil).envelope(), atR)
	r.settle()
	for _, rr := range r.co.of("resolution") {
		if rr.Record.Resolution["state"] == "reverted" {
			t.Fatalf("nothing was put back: %+v", rr.Record.Resolution)
		}
	}
}

// The live case end to end: a rule added, then removed ten minutes later, Config recording both without relatedEvents.
// Each Config item joins its own event, so the two diffs are inverse and the pair folds as a revert.
func TestAddThenRevokeWithoutRelatedEventsFoldsAsRevert(t *testing.T) {
	r := newRig(t)
	r.c.Rec = &Reconciler{Settle: 15 * time.Minute, Now: r.clk.now}
	r.clk.t = t0
	step := func(d time.Duration) {
		r.clk.add(d)
		if err := r.c.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	r.ingest(consoleSG("ev-add", t0).envelope(), t0)
	step(time.Minute)
	r.ingest(sgConfig(t0.Add(time.Minute)).envelope(), r.clk.t)
	step(9 * time.Minute)
	rv := revokeSG("ev-revoke", r.clk.t)
	r.ingest(rv.envelope(), r.clk.t)
	step(time.Minute)
	r.ingest(sgDelete(t0.Add(11*time.Minute)).envelope(), r.clk.t)
	for i := 0; i < 40; i++ {
		step(time.Minute)
	}
	if n := len(r.co.of("observation")); n != 2 {
		t.Fatalf("two observations: %d", n)
	}
	reverted := map[any]bool{}
	for _, rr := range r.co.of("resolution") {
		if rr.Record.Resolution["state"] == "reverted" {
			reverted[rr.Record.About["seq"]] = true
		}
	}
	if len(reverted) != 2 {
		t.Fatalf("both are resolved as reverted: %v", reverted)
	}
}
