package detect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

var t0 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

type fakePlan struct {
	exit  int
	addrs []string
	err   error
}

func (f fakePlan) Plan(context.Context, Workspace) (int, []string, error) {
	return f.exit, f.addrs, f.err
}

type fakeState []StateVersion

func (f fakeState) ListVersions(context.Context, string, string) ([]StateVersion, error) {
	return f, nil
}

type fakeTrail struct {
	puts  []PutEvent
	asked int
}

func (f *fakeTrail) StatePuts(context.Context, string, string, time.Time, time.Time) ([]PutEvent, error) {
	f.asked++
	return f.puts, nil
}

type fakeEv struct {
	outs     []Outcome
	reported []Reported
	err      error
}

func (f fakeEv) Outcomes(context.Context, time.Time) ([]Outcome, error)  { return f.outs, f.err }
func (f fakeEv) Reported(context.Context, time.Time) ([]Reported, error) { return f.reported, nil }

type fakeCore struct{ reqs []*client.RecordRequest }

func (f *fakeCore) Record(_ context.Context, r *client.RecordRequest) (*client.RecordRef, error) {
	f.reqs = append(f.reqs, r)
	return &client.RecordRef{Seq: int64(len(f.reqs))}, nil
}

var ws = Workspace{Name: "default", Key: "prod/net.tfstate", Bucket: "tf-state", Dir: ".", Env: "prod"}

func detector(p Planner, st State, tr *fakeTrail, ev fakeEv) (*Detector, *fakeCore) {
	c := &fakeCore{}
	return &Detector{Cfg: Config{Workspaces: []Workspace{ws}, Version: "0.1.0"}, Plan: p, State: st, Trail: tr, Ev: ev,
		Core: c, Now: func() time.Time { return t0 }}, c
}

func TestDriftFound(t *testing.T) {
	d, c := detector(fakePlan{exit: 2, addrs: []string{"aws_security_group.web", "aws_s3_bucket.logs"}}, nil, nil, fakeEv{})
	if err := d.Drift(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 1 {
		t.Fatal(len(c.reqs))
	}
	r := c.reqs[0]
	x := r.Record.Exception
	if r.Kind != "deploy.exception" || x["kind"] != "drift" || len(x["addresses"].([]string)) != 2 {
		t.Fatal(r)
	}
	w := r.Record.Destination["workspace"].(map[string]any)
	if w["backend"] != "s3" || w["key"] != ws.Key || w["name"] != "default" || r.Record.Destination["cluster"] != nil {
		t.Fatal(r.Record.Destination)
	}
	// the same drift, already filed, is not filed again
	d.Ev = fakeEv{reported: []Reported{{Kind: "drift", Backend: "s3", Key: ws.Key, Name: "default", Fingerprint: x["observed"].(string)}}}
	if err := d.Drift(context.Background()); err != nil || len(c.reqs) != 1 {
		t.Fatal(err, len(c.reqs))
	}
}

func TestNoDriftAndPlanFailure(t *testing.T) {
	d, c := detector(fakePlan{exit: 0}, nil, nil, fakeEv{})
	if err := d.Drift(context.Background()); err != nil || len(c.reqs) != 0 {
		t.Fatal(err, len(c.reqs))
	}
	d.Plan = fakePlan{exit: 1, err: errors.New("init needed")}
	if err := d.Drift(context.Background()); err == nil || len(c.reqs) != 0 {
		t.Fatal("a plan that could not run is an error, not an exception", err, len(c.reqs))
	}
}

func TestStateVersionMatchedToOutcome(t *testing.T) {
	v := StateVersion{"v1", t0.Add(-time.Hour)}
	ev := fakeEv{outs: []Outcome{{"prod", v.Modified.Add(-3 * time.Minute), v.Modified.Add(time.Minute)}}}
	tr := &fakeTrail{}
	d, c := detector(nil, fakeState{v}, tr, ev)
	if err := d.Untraced(context.Background()); err != nil || len(c.reqs) != 0 || tr.asked != 0 {
		t.Fatal(err, len(c.reqs), tr.asked)
	}
	// an outcome for another environment explains nothing
	ev.outs[0].Env = "dev"
	d, c = detector(nil, fakeState{v}, tr, ev)
	if err := d.Untraced(context.Background()); err != nil || len(c.reqs) != 1 {
		t.Fatal(err, len(c.reqs))
	}
}

func TestUntracedVersionNamesThePrincipal(t *testing.T) {
	v := StateVersion{"v9", t0.Add(-time.Hour)}
	old := StateVersion{"v0", t0.Add(-10 * time.Hour)} // outside the window
	fresh := StateVersion{"v10", t0.Add(-time.Minute)} // inside the settle time: its outcome may still come
	tr := &fakeTrail{puts: []PutEvent{{v.Modified.Add(10 * time.Second), "arn:aws:sts::123456789012:assumed-role/admin/dana"},
		{t0.Add(-5 * time.Hour), "arn:aws:iam::123456789012:user/other"}}}
	d, c := detector(nil, fakeState{old, v, fresh}, tr, fakeEv{})
	if err := d.Untraced(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 1 {
		t.Fatal(len(c.reqs))
	}
	x := c.reqs[0].Record.Exception
	st := x["state"].(map[string]any)
	if x["kind"] != "untraced-apply" || x["actor"] != "arn:aws:sts::123456789012:assumed-role/admin/dana" || st["version"] != "v9" ||
		st["key"] != ws.Key || *c.reqs[0].Record.Principal != x["actor"] {
		t.Fatal(x)
	}
	// filed once: the next run sees it reported
	d.Ev = fakeEv{reported: []Reported{{Kind: "untraced-apply", Backend: "s3", Key: ws.Key, Name: "default", Version: "v9"}}}
	if err := d.Untraced(context.Background()); err != nil || len(c.reqs) != 1 {
		t.Fatal(err, len(c.reqs))
	}
}

func TestUntracedWithoutTrailEventStillReports(t *testing.T) {
	d, c := detector(nil, fakeState{{"v9", t0.Add(-time.Hour)}}, &fakeTrail{}, fakeEv{})
	if err := d.Untraced(context.Background()); err != nil || len(c.reqs) != 1 || c.reqs[0].Record.Exception["actor"] != "unknown" {
		t.Fatal(err, c.reqs)
	}
}

func TestBlindOutcomeListReportsNothing(t *testing.T) {
	d, c := detector(nil, fakeState{{"v9", t0.Add(-time.Hour)}}, &fakeTrail{}, fakeEv{err: errors.New("503")})
	if err := d.Untraced(context.Background()); err == nil || len(c.reqs) != 0 {
		t.Fatal(err, len(c.reqs))
	}
}

func TestAddressesOf(t *testing.T) {
	got, err := AddressesOf([]byte(`{"resource_changes":[{"address":"a.x","change":{"actions":["no-op"]}},
	 {"address":"a.y","change":{"actions":["update"]}},{"address":"a.z","change":{"actions":["delete","create"]}}]}`))
	if err != nil || strings.Join(got, ",") != "a.y,a.z" {
		t.Fatal(got, err)
	}
	if _, err := AddressesOf([]byte(`{"resource_changes": [`)); err == nil {
		t.Fatal("unparseable plan JSON must be an error, not an empty drift")
	}
}

// AWS's published SigV4 test vector (get-vanilla).
func TestSigV4Vector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	Sign(req, nil, Creds{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "service", "us-east-1",
		time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("%s\nwant %s", got, want)
	}
}

func TestAWSOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AK/") {
			http.Error(w, "unsigned", 403)
			return
		}
		if r.Method == "GET" { // S3 ListObjectVersions, path style: /tf-state/?versions&prefix=...
			if r.URL.Path != "/tf-state/" || r.URL.Query().Get("prefix") != "prod/net.tfstate" {
				http.Error(w, r.URL.String(), 400)
				return
			}
			w.Write([]byte(`<ListVersionsResult><IsTruncated>false</IsTruncated>
			 <Version><Key>prod/net.tfstate</Key><VersionId>v1</VersionId><LastModified>2026-11-07T11:00:00.000Z</LastModified></Version>
			 <Version><Key>prod/net.tfstate.backup</Key><VersionId>x</VersionId><LastModified>2026-11-07T11:00:00.000Z</LastModified></Version></ListVersionsResult>`))
			return
		}
		if r.Header.Get("X-Amz-Target") != "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents" {
			http.Error(w, "target", 400)
			return
		}
		ev, _ := json.Marshal(map[string]any{"userIdentity": map[string]any{"arn": "arn:aws:iam::1:user/dana"},
			"requestParameters": map[string]any{"bucketName": "tf-state", "key": "prod/net.tfstate"}})
		other, _ := json.Marshal(map[string]any{"userIdentity": map[string]any{"arn": "arn:aws:iam::1:user/x"},
			"requestParameters": map[string]any{"bucketName": "tf-state", "key": "elsewhere"}})
		json.NewEncoder(w).Encode(map[string]any{"Events": []map[string]any{
			{"EventTime": 1.7940528e9, "CloudTrailEvent": string(ev)}, {"EventTime": 1.7940528e9, "CloudTrailEvent": string(other)}}})
	}))
	defer srv.Close()
	a := &AWS{Region: "us-east-1", S3Endpoint: srv.URL, TrailEndpoint: srv.URL, HTTP: srv.Client(), Now: func() time.Time { return t0 },
		Creds: func(context.Context, *http.Client, string) (Creds, error) {
			return Creds{AccessKey: "AK", SecretKey: "SK", Token: "TOK"}, nil
		}}
	vs, err := a.ListVersions(context.Background(), "tf-state", "prod/net.tfstate")
	if err != nil || len(vs) != 1 || vs[0].ID != "v1" || !vs[0].Modified.Equal(time.Date(2026, 11, 7, 11, 0, 0, 0, time.UTC)) {
		t.Fatal(vs, err)
	}
	ps, err := a.StatePuts(context.Background(), "tf-state", "prod/net.tfstate", t0.Add(-time.Hour), t0)
	if err != nil || len(ps) != 1 || ps[0].Principal != "arn:aws:iam::1:user/dana" {
		t.Fatal(ps, err)
	}
}

// A real STS AssumeRoleWithWebIdentity answer (XML, the default), with AWS's documentation example values.
func TestParseSTS(t *testing.T) {
	c, err := parseSTS([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A</SubjectFromWebIdentityToken>
    <Audience>client.5498841531868486423.1548@apps.example.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/FederatedWebIdentityRole/app1</Arn>
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:app1</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <SessionToken>AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2026-11-07T13:00:00Z</Expiration>
      <AccessKeyId>ASIACLKWSDQRAOEXAMPLE</AccessKeyId>
    </Credentials>
    <Provider>www.amazon.com</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`))
	if err != nil || !c.Expires.Equal(time.Date(2026, 11, 7, 13, 0, 0, 0, time.UTC)) || c.AccessKey != "ASIACLKWSDQRAOEXAMPLE" || c.SecretKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY" ||
		!strings.HasPrefix(c.Token, "AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp") {
		t.Fatal(c, err)
	}
	if _, err := parseSTS([]byte(`<AssumeRoleWithWebIdentityResponse></AssumeRoleWithWebIdentityResponse>`)); err == nil {
		t.Fatal("an answer with no credentials is an error")
	}
}

// One workspace's filed drift does not suppress another's (same key, other workspace name), and a drift with no
// resource addresses is counted as zero in its detail.
func TestReportedMatchesTheWholeWorkspace(t *testing.T) {
	d, c := detector(fakePlan{exit: 2, addrs: []string{"a.x"}}, nil, nil, fakeEv{})
	d.Ev = fakeEv{reported: []Reported{{Kind: "drift", Backend: "s3", Key: ws.Key, Name: "staging", Fingerprint: Fingerprint([]string{"a.x"})}}}
	if err := d.Drift(context.Background()); err != nil || len(c.reqs) != 1 {
		t.Fatal(err, len(c.reqs))
	}
	d, c = detector(fakePlan{exit: 2}, nil, nil, fakeEv{})
	if err := d.Drift(context.Background()); err != nil || len(c.reqs) != 1 {
		t.Fatal(err, len(c.reqs))
	}
	if det := c.reqs[0].Record.Exception["detail"].(string); !strings.Contains(det, " 0 address(es)") {
		t.Fatal(det)
	}
}

func TestDriftDedupUsesItsOwnLookback(t *testing.T) {
	var asked time.Time
	d, _ := detector(fakePlan{exit: 0}, nil, nil, fakeEv{})
	d.Ev = sinceEv{&asked}
	if err := d.Drift(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := t0.Sub(asked); got != 7*24*time.Hour {
		t.Fatalf("drift de-duplication looks back %s, want 7 days (not the 2h window)", got)
	}
}

type sinceEv struct{ since *time.Time }

func (s sinceEv) Outcomes(context.Context, time.Time) ([]Outcome, error) { return nil, nil }
func (s sinceEv) Reported(_ context.Context, since time.Time) ([]Reported, error) {
	*s.since = since
	return nil, nil
}

func TestCredentialsMintedOnceAndRefreshedBeforeExpiry(t *testing.T) {
	now, minted := t0, 0
	a := &AWS{Now: func() time.Time { return now }, Creds: func(context.Context, *http.Client, string) (Creds, error) {
		minted++
		return Creds{AccessKey: "AK", SecretKey: "SK", Expires: now.Add(15 * time.Minute)}, nil
	}}
	for i := 0; i < 5; i++ {
		if _, err := a.credentials(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if minted != 1 {
		t.Fatalf("minted %d times for 5 requests", minted)
	}
	now = t0.Add(14 * time.Minute) // inside the 2 minute refresh margin
	a.credentials(context.Background())
	if minted != 2 {
		t.Fatalf("minted %d, want a refresh near expiry", minted)
	}
}
