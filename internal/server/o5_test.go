package server_test

// O-5: a person sets an observation's resolution cause through the core (append-only, naming the person), and the S3
// trail's verification reaches the evidence of an observation the EventBridge copy recorded first.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"github.com/jfillman/clearance/providers/observe-aws/collector"
	awsscope "github.com/jfillman/clearance/providers/observe-aws/scope"
)

const awsProviders = `[{"name": "observe-aws", "version": "0.1.0", "principals": ["observed-system/observe-aws"],
 "kinds": ["observation", "assessment", "resolution", "observation.health", "observation.verification"]}]`

func awsFixture(t *testing.T, providers string) (*fixture, *client.Client) {
	t.Helper()
	vocabtest.Use(t, vocabtest.Lab())
	ps, err := server.ParseProviders(providers)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, "")
	cfg.Providers = ps
	f := newFixture(t, cfg)
	cc, err := client.New(client.Options{BaseURL: f.srv.URL, Token: client.StaticToken("observed-system/observe-aws"), Provider: "observe-aws", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return f, cc
}

func seqOfRec(r store.Record) int64 {
	n, _ := gate.SeqInt(r["seq"])
	return n
}

func TestAPersonSetsAResolutionCauseAndTheRecordNamesThem(t *testing.T) {
	f, cc := awsFixture(t, awsProviders)
	ctx := context.Background()
	const acct = "111122223333"
	if _, err := cc.Record(ctx, &client.RecordRequest{Kind: "observation.health", Record: client.ProviderEvent{Scope: client.String(acct),
		Source: map[string]any{"name": "observe-aws"}, Health: map[string]any{"state": "healthy", "interval_seconds": 300,
			"checks": []any{map[string]any{"name": "trail-enabled", "ok": true}}}}}); err != nil {
		t.Fatal(err)
	}
	obsRef, err := cc.Record(ctx, &client.RecordRequest{Kind: "observation", Record: client.ProviderEvent{Scope: client.String(acct),
		Source:    map[string]any{"name": "observe-aws", "event_id": "ev-1"},
		Resource:  map[string]any{"kind": "s3", "id": "bucket-1"},
		Actor:     map[string]any{"subject": "dana@example.com"},
		Action:    map[string]any{"verb": "PutBucketPolicy", "api": "PutBucketPolicy", "succeeded": true},
		Integrity: map[string]any{"sourceVerified": false, "completenessClaimed": true},
		Times:     map[string]any{"observed": time.Now().UTC().Format(time.RFC3339)}}})
	if err != nil {
		t.Fatal(err)
	}
	about := obsRef.Seq
	path := func(seq int64) string {
		return "/v1/observations/" + json.Number(strings.TrimSpace(jsonInt(seq))).String() + "/resolution"
	}
	body := map[string]any{"state": "reverted", "cause": "human-initiated", "note": "Dana rolled it back from the console"}

	// who may: a person who is an admin; another person, a service and a non-person are refused.
	f.do("POST", path(about), "user:dana", body).want(t, 403, "not a Clearance admin")
	f.do("POST", path(about), gw, body).want(t, 403, "")
	f.do("POST", path(about), "", body).want(t, 401, "")
	if n := countTool(f, "resolution"); n != 0 {
		t.Fatalf("a refused call wrote %d resolution records", n)
	}
	// what: the seven causes only, reverted only, an observation only, a body of the three fields only.
	f.do("POST", path(about), "user:admin", map[string]any{"state": "reverted", "cause": "bad-luck"}).want(t, 400, "cause")
	f.do("POST", path(about), "user:admin", map[string]any{"state": "reverted"}).want(t, 400, "cause")
	f.do("POST", path(about), "user:admin", map[string]any{"state": "ratified", "cause": "human-initiated"}).want(t, 400, "cause")
	f.do("POST", path(about), "user:admin", map[string]any{"state": "fixed"}).want(t, 400, "state")
	f.do("POST", path(about), "user:admin", map[string]any{"state": "ratified", "by": "user:someone-else"}).want(t, 400, "")
	f.do("POST", path(about), "user:admin", `{"state": `).want(t, 400, "")
	f.do("POST", path(about+1), "user:admin", body).want(t, 404, "")
	f.do("POST", path(0), "user:admin", body).want(t, 404, "not an observation")
	f.do("POST", "/v1/observations/abc/resolution", "user:admin", body).want(t, 400, "seq")
	if n := countTool(f, "resolution"); n != 0 {
		t.Fatalf("refused calls wrote %d resolution records", n)
	}
	for _, cause := range observe.RevertCauses { // every one of the seven is accepted
		f.do("POST", path(about), "user:admin", map[string]any{"state": "reverted", "cause": cause}).want(t, 200, "")
	}

	// the edit is a new record; the first stays. The newest wins when it is read, and names the person.
	first := f.do("POST", path(about), "user:admin", body).want(t, 200, "")
	if first.body["by"] != "user:admin" || first.body["cause"] != "human-initiated" || first.body["via"] != nil || first.body["about"] != float64(about) {
		t.Fatalf("answer: %v", first.body)
	}
	// a delegate (Tower's backend) naming the admin
	req, _ := http.NewRequest("POST", f.srv.URL+path(about), strings.NewReader(`{"state": "ratified", "note": "accepted at the change review"}`))
	req.Header.Set("Authorization", "Bearer "+tower)
	req.Header.Set(vocab.Get().OnBehalfOfHeader, "user:admin")
	via := f.send(req).want(t, 200, "")
	if via.body["by"] != "user:admin" || via.body["via"] != tower {
		t.Fatalf("a delegate's answer names the person and the delegate: %v", via.body)
	}

	var resolutions []store.Record
	var observation store.Record
	for _, r := range f.records() {
		switch r["tool"] {
		case "resolution":
			resolutions = append(resolutions, r)
		case "observation":
			observation = r
		}
	}
	if len(resolutions) != len(observe.RevertCauses)+2 {
		t.Fatalf("%d resolution records: every edit is a record", len(resolutions))
	}
	r := resolutions[len(resolutions)-2] // the human-initiated one
	res := r["resolution"].(map[string]any)
	if r["principal"] != "user:admin" || res["by"] != "user:admin" || res["cause"] != "human-initiated" || res["note"] == "" ||
		r["initiator"].(map[string]any)["sub"] != "user:admin" || r["coverage"] != "observed-not-attributed" {
		t.Fatalf("the record names the person: %v", r)
	}
	if v, _ := r["verified"].([]any); !containsAny(v, "initiator") || !containsAny(v, "about") || containsAny(r["claimed"].([]any), "initiator") {
		t.Fatalf("the person is established by the core, not claimed: verified %v claimed %v", r["verified"], r["claimed"])
	}
	lastVia := resolutions[len(resolutions)-1]
	if containsAny(lastVia["verified"].([]any), "initiator") || lastVia["initiator"].(map[string]any)["iss"] != "delegate:"+tower {
		t.Fatalf("a delegate's record does not claim the person signed in: %v", lastVia)
	}
	// read as the statement does: the newest record wins
	st := observe.Build(observe.Input{Scope: acct, Window: observe.Window{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Minute)},
		Observations: []observe.Record{observation}, Resolutions: recordsOf(resolutions)}, time.Now())
	it := st.Seen.Items[0]
	if it.Resolution == nil || *it.Resolution != "ratified" || it.ResolvedBy == nil || *it.ResolvedBy != "user:admin" || it.ResolutionSeq == nil ||
		*it.ResolutionSeq != seqOfRec(lastVia) {
		t.Fatalf("the newest resolution wins: %+v", it)
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func containsAny(l []any, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func recordsOf(rs []store.Record) []observe.Record {
	out := make([]observe.Record, len(rs))
	for i, r := range rs {
		out[i] = r
	}
	return out
}

func countTool(f *fixture, tool string) int {
	n := 0
	for _, r := range f.records() {
		if r["tool"] == tool {
			n++
		}
	}
	return n
}

// The trail's verified copy of an event the EventBridge copy recorded first: one observation, one exception, one
// verification record, and the statement counts it.
func TestTrailVerificationReachesTheEvidenceOfAnEventAlreadyRecorded(t *testing.T) {
	f, cc := awsFixture(t, awsProviders)
	const acct = "111122223333"
	const sso = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef"
	now := time.Now().UTC().Add(-time.Minute)
	rs, _ := pipeline.Default()
	col := &collector.Collector{Cfg: collector.Config{Accounts: []string{acct}}, Pipe: pipeline.New(rs, nil, vocab.Vocabulary{}),
		Filter: &awsscope.Filter{}, Rec: &collector.Reconciler{Settle: time.Nanosecond}, Core: cc}
	ctx := context.Background()
	if _, err := cc.Record(ctx, &client.RecordRequest{Kind: "observation.health", Record: client.ProviderEvent{Scope: client.String(acct),
		Source: map[string]any{"name": "observe-aws"}, Health: map[string]any{"state": "healthy", "interval_seconds": 300,
			"checks": []any{map[string]any{"name": "trail-enabled", "ok": true}}}}}); err != nil {
		t.Fatal(err)
	}
	raw := func(id string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"eventID": id, "eventName": "PutBucketPolicy", "eventSource": "s3.amazonaws.com", "eventTime": now.Format(time.RFC3339),
			"awsRegion": "us-east-1", "recipientAccountId": acct, "userAgent": "console", "requestParameters": map[string]any{"bucketName": "clearance-state"},
			"userIdentity": map[string]any{"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/dana",
				"sessionContext": map[string]any{"sessionIssuer": map[string]any{"arn": sso}, "sourceIdentity": "dana@example.com"}}})
		return b
	}
	ingest := func(feed, method string, verified bool, id string) {
		t.Helper()
		if err := col.Ingest(&collector.Item{Feed: feed, Raw: raw(id), Verified: verified, Method: method, Received: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	step := func() {
		t.Helper()
		time.Sleep(5 * time.Millisecond)
		if err := col.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	count := func(tool string) (n int, last store.Record) {
		for _, r := range f.records() {
			if r["tool"] == tool {
				n, last = n+1, r
			}
		}
		return
	}

	// 1. EventBridge first, then the trail an hour later: the case O-4 lost.
	ingest(collector.FeedEventBridge, collector.MethodEventBridge, false, "ev-late")
	step()
	n, ob := count("observation")
	if n != 1 || ob["integrity"].(map[string]any)["sourceVerified"] != false {
		t.Fatalf("one observation, not verified yet: %d %v", n, ob["integrity"])
	}
	ingest(collector.FeedTrail, collector.MethodDigestChain, true, "ev-late")
	step()
	step() // a second pass changes nothing
	if n, _ := count("observation"); n != 1 {
		t.Fatalf("the trail's copy is not a second observation: %d", n)
	}
	if n, _ := count("assessment"); n != 1 {
		t.Fatalf("nor a second assessment (so no second exception): %d", n)
	}
	vn, ver := count("observation.verification")
	if vn != 1 || ver["about"].(map[string]any)["seq"] != ob["seq"] || ver["verification"].(map[string]any)["verified"] != true ||
		ver["verification"].(map[string]any)["method"] != collector.MethodDigestChain || ver["scope"] != acct {
		t.Fatalf("one verification about the observation: %d %v", vn, ver)
	}
	if ob["integrity"].(map[string]any)["sourceVerified"] != false {
		t.Fatal("the observation was not rewritten")
	}
	if c := col.Stats(); c.Verifications != 1 || c.VerificationsRefused != 0 {
		t.Fatalf("stats %+v", c)
	}
	// a redelivery of the trail copy is the core's duplicate
	ingest(collector.FeedTrail, collector.MethodDigestChain, true, "ev-late")
	step()
	if vn, _ := count("observation.verification"); vn != 1 {
		t.Fatalf("a redelivery adds no second verification: %d", vn)
	}

	// 2. Both copies pending at once: one observation, posted verified, no verification record needed.
	ingest(collector.FeedEventBridge, collector.MethodEventBridge, false, "ev-both")
	ingest(collector.FeedTrail, collector.MethodDigestChain, true, "ev-both")
	step()
	n, _ = count("observation")
	var both store.Record
	for _, r := range f.records() {
		if r["tool"] == "observation" && r["source"].(map[string]any)["event_id"] == "ev-both" {
			both = r
		}
	}
	if n != 2 || both == nil || both["integrity"].(map[string]any)["sourceVerified"] != true {
		t.Fatalf("both copies pending: one observation, verified: %d %v", n, both)
	}
	if vn, _ := count("observation.verification"); vn != 1 {
		t.Fatalf("no verification record for an observation posted verified: %d", vn)
	}

	// 3. The statement counts what the trail verified, once.
	var obs, ass, vers []observe.Record
	for _, r := range f.records() {
		switch r["tool"] {
		case "observation":
			obs = append(obs, r)
		case "assessment":
			ass = append(ass, r)
		case "observation.verification":
			vers = append(vers, r)
		}
	}
	st := observe.Build(observe.Input{Scope: acct, Window: observe.Window{From: now.Add(-time.Hour), To: time.Now().Add(time.Minute)},
		Observations: obs, Assessments: ass, Verifications: vers}, time.Now())
	if si := st.Integrity; si.Observations != 2 || si.Verified != 2 || si.Own != 1 || si.Later != 1 || si.Unverified != 0 {
		t.Fatalf("source integrity %+v", si)
	}

	// 4. A verification about another source's observation, or about a record that is not an observation, is refused.
	other := f.do("POST", "/v1/records", "observed-system/observe-aws", map[string]any{"provider": "observe-aws", "kind": "observation.verification",
		"record": map[string]any{"scope": acct, "source": map[string]any{"name": "another-feed", "event_id": "x/verification"},
			"about": map[string]any{"seq": seqOfRec(ob)}, "verification": map[string]any{"method": "m", "verified": true}}})
	other.want(t, 400, "only its own")
	f.do("POST", "/v1/records", "observed-system/observe-aws", map[string]any{"provider": "observe-aws", "kind": "observation.verification",
		"record": map[string]any{"scope": acct, "source": map[string]any{"name": "observe-aws", "event_id": "y/verification"},
			"about": map[string]any{"seq": 0}, "verification": map[string]any{"method": "m", "verified": true}}}).want(t, 400, "")
	f.do("POST", "/v1/records", "observed-system/observe-aws", map[string]any{"provider": "observe-aws", "kind": "observation.verification",
		"record": map[string]any{"scope": acct, "source": map[string]any{"name": "observe-aws", "event_id": "z/verification"},
			"about": map[string]any{"seq": seqOfRec(ob)}, "verification": map[string]any{"method": "m", "verified": false}}}).want(t, 400, "verified")
}

// A collector registered before this kind existed keeps working: the core refuses the verification, the collector
// counts it and goes on, and the observation keeps sourceVerified false.
func TestCollectorWithoutTheVerificationKindKeepsWorking(t *testing.T) {
	f, cc := awsFixture(t, `[{"name": "observe-aws", "version": "0.1.0", "principals": ["observed-system/observe-aws"],
	  "kinds": ["observation", "assessment", "resolution", "observation.health"]}]`)
	const acct = "111122223333"
	now := time.Now().UTC().Add(-time.Minute)
	rs, _ := pipeline.Default()
	col := &collector.Collector{Cfg: collector.Config{Accounts: []string{acct}}, Pipe: pipeline.New(rs, nil, vocab.Vocabulary{}),
		Filter: &awsscope.Filter{}, Rec: &collector.Reconciler{Settle: time.Nanosecond}, Core: cc}
	b, _ := json.Marshal(map[string]any{"eventID": "ev-old", "eventName": "PutBucketPolicy", "eventSource": "s3.amazonaws.com", "eventTime": now.Format(time.RFC3339),
		"awsRegion": "us-east-1", "recipientAccountId": acct, "requestParameters": map[string]any{"bucketName": "clearance-state"},
		"userIdentity": map[string]any{"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dana"}})
	for i, v := range []bool{false, true} {
		feed, method := collector.FeedEventBridge, collector.MethodEventBridge
		if v {
			feed, method = collector.FeedTrail, collector.MethodDigestChain
		}
		if err := col.Ingest(&collector.Item{Feed: feed, Raw: b, Verified: v, Method: method, Received: time.Now()}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		if err := col.Step(context.Background()); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if c := col.Stats(); c.VerificationsRefused != 1 || c.Verifications != 0 {
		t.Fatalf("stats %+v", c)
	}
	if n := countTool(f, "observation"); n != 1 {
		t.Fatalf("%d observations", n)
	}
}
