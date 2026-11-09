package server_test

// O-4: the observe-aws collector through the whole core over HTTP: a console change is an exception with its actor,
// its Config diff and a resolution, a gated apply is not, a StopLogging flips the account's health, and a redelivery
// is the core's duplicate. The collector's own logic is tested in providers/observe-aws/collector; this proves the
// records it builds are ones the core accepts.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"github.com/jfillman/clearance/providers/observe-aws/collector"
	"github.com/jfillman/clearance/providers/observe-aws/detect"
	awsscope "github.com/jfillman/clearance/providers/observe-aws/scope"
)

type applies []detect.Apply

func (a applies) Applies(context.Context, time.Time) ([]detect.Apply, error) { return a, nil }

func TestObserveAWSThroughTheCore(t *testing.T) {
	vocabtest.Use(t, vocabtest.Lab())
	ps, err := server.ParseProviders(`[{"name": "autopilot-gateway", "version": "0.3.27", "principals": ["autopilot-system/clearance"]},
	  {"name": "observe-aws", "version": "0.1.0", "principals": ["observed-system/observe-aws"],
	   "kinds": ["observation", "assessment", "resolution", "observation.health"]}]`)
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
	const acct = "111122223333"
	const sso = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef"
	const apply = "arn:aws:iam::111122223333:role/clearance-apply"
	digest := "sha256:" + string(make([]byte, 0)) + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Now().UTC().Add(-time.Minute)

	rs, _ := pipeline.Default()
	lk := &collector.EvidenceLookups{Src: applies{{Change: "clr_apply1", Env: "lab", Digest: digest, Started: now.Add(-time.Minute), Finished: now.Add(time.Minute)}},
		ScopeEnv: map[string]string{acct: "lab"}}
	col := &collector.Collector{Cfg: collector.Config{Accounts: []string{acct}}, Pipe: pipeline.New(rs, lk, vocab.Vocabulary{}),
		Filter: &awsscope.Filter{}, Rec: &collector.Reconciler{Settle: time.Nanosecond}, Core: cc, Lookups: lk}

	// a healthy feed first, so completeness is supported
	if _, err := cc.Record(context.Background(), &client.RecordRequest{Kind: "observation.health", Record: client.ProviderEvent{Scope: client.String(acct),
		Source: map[string]any{"name": "observe-aws"}, Health: map[string]any{"state": "healthy", "interval_seconds": 300,
			"checks": []any{map[string]any{"name": "trail-enabled", "ok": true}}}}}); err != nil {
		t.Fatal(err)
	}
	rec := func(id, name, source, issuer, arn, srcID, ua string, params map[string]any) []byte {
		sc := map[string]any{"sessionIssuer": map[string]any{"arn": issuer}, "sourceIdentity": srcID}
		b, _ := json.Marshal(map[string]any{"detail-type": "AWS API Call via CloudTrail", "detail": map[string]any{
			"eventID": id, "eventName": name, "eventSource": source, "eventTime": now.Format(time.RFC3339), "awsRegion": "us-east-1",
			"recipientAccountId": acct, "userAgent": ua, "requestParameters": params,
			"userIdentity": map[string]any{"type": "AssumedRole", "arn": arn, "sessionContext": sc}}})
		return b
	}
	cfgItem, _ := json.Marshal(map[string]any{"detail-type": "Config Configuration Item Change", "account": acct, "region": "us-east-1", "detail": map[string]any{
		"configurationItemDiff": map[string]any{"changeType": "UPDATE", "changedProperties": map[string]any{
			"Configuration.IpPermissions.0": map[string]any{"changeType": "CREATE", "updatedValue": map[string]any{"fromPort": 22}}}},
		"configurationItem": map[string]any{"configurationItemCaptureTime": now.Add(20 * time.Second).Format(time.RFC3339), "resourceType": "AWS::EC2::SecurityGroup",
			"resourceId": "sg-0abc1234", "awsAccountId": acct, "awsRegion": "us-east-1", "relatedEvents": []string{"ev-console"}}}})
	for _, body := range [][]byte{
		rec("ev-console", "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", sso, "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/dana", "dana@example.com", "console", map[string]any{"groupId": "sg-0abc1234"}),
		cfgItem,
		rec("ev-gated", "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", apply, "arn:aws:sts::111122223333:assumed-role/clearance-apply/tf-run-77", "run=77",
			"Terraform/1.13 clearance/grant=clr_apply1;plan="+digest, map[string]any{"groupId": "sg-0zzz"}),
		rec("ev-stop", "StopLogging", "cloudtrail.amazonaws.com", sso, "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/dana", "dana@example.com", "console", map[string]any{"name": "organization"}),
	} {
		it, err := collector.ParseMessage(body, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := col.Ingest(it); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(10 * time.Millisecond)
	if err := col.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := col.Step(context.Background()); err != nil { // a second pass changes nothing
		t.Fatal(err)
	}

	var obs, assess, res, flips []map[string]any
	for _, r := range f.records() {
		switch r["tool"] {
		case "observation":
			obs = append(obs, r)
		case "assessment":
			assess = append(assess, r)
		case "resolution":
			res = append(res, r)
		case "observation.health":
			if h, _ := r["health"].(map[string]any); h["state"] == "blind" {
				flips = append(flips, r)
			}
		}
	}
	if len(obs) != 3 || len(assess) != 3 {
		t.Fatalf("three changes (the console change with its Config item counts once): %d observations %d assessments", len(obs), len(assess))
	}
	byEvent := map[string]map[string]any{}
	for _, o := range obs {
		byEvent[o["source"].(map[string]any)["event_id"].(string)] = o
	}
	con := byEvent["ev-console"]
	if con["actor"].(map[string]any)["subject"] != "dana@example.com" || con["state_change"] == nil {
		t.Fatalf("actor and Config diff: %v", con)
	}
	cov := map[string]string{}
	for _, a := range assess {
		about, _ := a["about"].(map[string]any)
		for _, o := range obs {
			if o["seq"] == about["seq"] {
				cov[o["source"].(map[string]any)["event_id"].(string)] = a["coverage"].(string)
			}
		}
	}
	if cov["ev-console"] != "out-of-band-detected" || cov["ev-gated"] != "authorized-and-verified" || cov["ev-stop"] == "authorized-and-verified" {
		t.Fatalf("%v", cov)
	}
	if len(res) != 2 { // the console change and the StopLogging; the gated apply has nothing to resolve
		t.Fatalf("%d resolutions", len(res))
	}
	if len(flips) != 1 {
		t.Fatalf("a successful StopLogging flips the account to blind: %d", len(flips))
	}
}
