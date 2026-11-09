package collector

import (
	"context"
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
