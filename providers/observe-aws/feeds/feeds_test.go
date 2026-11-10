package feeds

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/providers/observe-aws/detect"
)

func api(t *testing.T, h http.HandlerFunc) *API {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	a := &detect.AWS{Region: "us-east-1", HTTP: srv.Client(), Now: func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) },
		Creds: func(context.Context, *http.Client, string) (detect.Creds, error) {
			return detect.Creds{AccessKey: "AK", SecretKey: "SK", Token: "TOK"}, nil
		}}
	return &API{AWS: a, EP: Endpoints{S3: srv.URL, SQS: srv.URL, CloudTrail: srv.URL, Config: srv.URL, Events: srv.URL}}
}

func target(r *http.Request) string { return r.Header.Get("X-Amz-Target") }

func TestS3ListAndGetWithMetadata(t *testing.T) {
	a := api(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			http.Error(w, "unsigned", 403)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			if r.URL.Query().Get("continuation-token") == "" {
				w.Write([]byte(`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken><Contents><Key>a</Key></Contents></ListBucketResult>`))
				return
			}
			w.Write([]byte(`<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>b</Key></Contents></ListBucketResult>`))
			return
		}
		if r.URL.Path != "/trail/AWSLogs/o-1/CloudTrail-Digest/x_1.json.gz" {
			http.Error(w, r.URL.Path, 404)
			return
		}
		w.Header().Set("x-amz-meta-signature", "abcd")
		w.Header().Set("x-amz-meta-signature-algorithm", "SHA256withRSA")
		w.Write([]byte("body"))
	})
	s := S3{API: a}
	keys, err := s.List(context.Background(), "trail", "AWSLogs/")
	if err != nil || strings.Join(keys, ",") != "a,b" {
		t.Fatal(keys, err)
	}
	b, meta, err := s.Get(context.Background(), "trail", "AWSLogs/o-1/CloudTrail-Digest/x_1.json.gz")
	if err != nil || string(b) != "body" || meta["signature"] != "abcd" || meta["signature-algorithm"] != "SHA256withRSA" {
		t.Fatal(string(b), meta, err)
	}
	if _, _, err := s.Get(context.Background(), "trail", "missing"); err == nil {
		t.Fatal("a 404 is an error")
	}
}

func TestSQSReceiveAndDelete(t *testing.T) {
	var deleted string
	a := api(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in map[string]any
		json.Unmarshal(b, &in)
		if in["QueueUrl"] != "https://sqs.us-east-1.amazonaws.com/111122223333/observe-aws" {
			http.Error(w, "queue", 400)
			return
		}
		switch target(r) {
		case "AmazonSQS.ReceiveMessage":
			json.NewEncoder(w).Encode(map[string]any{"Messages": []map[string]any{{"MessageId": "m1", "ReceiptHandle": "h1", "Body": "{}"}}})
		case "AmazonSQS.DeleteMessage":
			deleted, _ = in["ReceiptHandle"].(string)
			w.Write([]byte("{}"))
		default:
			http.Error(w, target(r), 400)
		}
	})
	q := &SQS{API: a, QueueURL: "https://sqs.us-east-1.amazonaws.com/111122223333/observe-aws"}
	ms, err := q.Receive(context.Background())
	if err != nil || len(ms) != 1 || ms[0].Handle != "h1" {
		t.Fatal(ms, err)
	}
	if err := q.Delete(context.Background(), "h1"); err != nil || deleted != "h1" {
		t.Fatal(deleted, err)
	}
}

func TestPublicKeysByFingerprint(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	calls := 0
	a := api(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if target(r) != trailTarget+"ListPublicKeys" {
			http.Error(w, target(r), 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"PublicKeyList": []map[string]any{{"Value": base64.StdEncoding.EncodeToString(der), "Fingerprint": "fp1"}}})
	})
	p := &PublicKeys{API: a}
	got, err := p.PublicKey("fp1", time.Now())
	if err != nil || got.N.Cmp(k.N) != 0 {
		t.Fatal(err)
	}
	if _, err := p.PublicKey("fp1", time.Now()); err != nil || calls != 1 {
		t.Fatalf("a key once learned is kept: %d calls, %v", calls, err)
	}
	if _, err := p.PublicKey("nope", time.Now()); err == nil {
		t.Fatal("an unknown fingerprint is an error")
	}
}

func TestTrailsRecordersAndRules(t *testing.T) {
	a := api(t, func(w http.ResponseWriter, r *http.Request) {
		switch target(r) {
		case trailTarget + "DescribeTrails":
			json.NewEncoder(w).Encode(map[string]any{"trailList": []map[string]any{{"Name": "organization", "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/organization",
				"IsMultiRegionTrail": true, "IsOrganizationTrail": true, "LogFileValidationEnabled": true}}})
		case trailTarget + "GetTrailStatus":
			w.Write([]byte(`{"IsLogging": true}`))
		case trailTarget + "GetEventSelectors":
			w.Write([]byte(`{"EventSelectors":[{"ReadWriteType":"WriteOnly","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::tf-state/"]}]}],
			 "AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.ARN","StartsWith":["arn:aws:s3:::artifacts/"]}]}]}`))
		case "StarlingDoveService.DescribeConfigurationRecorderStatus":
			w.Write([]byte(`{"ConfigurationRecordersStatus":[{"name":"default","recording":true,"lastStatus":"SUCCESS"}]}`))
		case "AWSEvents.DescribeRule":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "missing") {
				w.WriteHeader(400)
				w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
				return
			}
			w.Write([]byte(`{"Name":"observe-aws-cloudtrail","State":"ENABLED"}`))
		default:
			http.Error(w, target(r), 400)
		}
	})
	ts, err := a.Trails(context.Background())
	if err != nil || len(ts) != 1 {
		t.Fatal(ts, err)
	}
	s := ts[0]
	if !s.Logging || !s.MultiRegion || !s.Organization || !s.LogValidation || !s.Management || s.ReadWrite != "WriteOnly" ||
		strings.Join(s.DataBuckets, ",") != "tf-state,artifacts" {
		t.Fatalf("%+v", s)
	}
	rs, err := a.Recorders(context.Background())
	if err != nil || len(rs) != 1 || !rs[0].Recording || rs[0].LastStatus != "SUCCESS" {
		t.Fatal(rs, err)
	}
	ru, err := a.Rules(context.Background(), []string{"observe-aws-cloudtrail", "missing"})
	if err != nil || len(ru) != 2 || ru[0].State != "ENABLED" || ru[1].State != "" {
		t.Fatal(ru, err)
	}
}

// S3 serves CloudTrail objects with Content-Encoding: gzip. Go's transport decompresses them unless the request sets
// Accept-Encoding itself; Get does, so the collector receives the stored bytes (gzip magic), as the digest code expects.
func TestS3GetDoesNotLetTheTransportDecompress(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write([]byte(`{"digest":true}`))
	zw.Close()
	a := api(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Write(zb.Bytes())
	})
	b, _, err := (S3{API: a}).Get(context.Background(), "trail", "k.json.gz")
	if err != nil || len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Fatalf("%x %v", b, err)
	}
}

// A member account sees the organization trail (a shadow of the management account's) but cannot read its status: the
// account's reader leaves it out and reads the trail the account owns.
func TestTrailsInSkipsTrailsOfOtherAccounts(t *testing.T) {
	a := api(t, func(w http.ResponseWriter, r *http.Request) {
		switch target(r) {
		case trailTarget + "DescribeTrails":
			json.NewEncoder(w).Encode(map[string]any{"trailList": []map[string]any{
				{"Name": "organization", "TrailARN": "arn:aws:cloudtrail:us-east-1:158233516926:trail/organization", "IsOrganizationTrail": true},
				{"Name": "observe-data", "TrailARN": "arn:aws:cloudtrail:us-east-1:700017004810:trail/observe-data", "LogFileValidationEnabled": true}}})
		case trailTarget + "GetTrailStatus":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "158233516926") {
				http.Error(w, "the owner's", 403)
				return
			}
			w.Write([]byte(`{"IsLogging": true}`))
		case trailTarget + "GetEventSelectors":
			w.Write([]byte(`{"EventSelectors":[{"IncludeManagementEvents":false,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::tf-state/"]}]}]}`))
		default:
			http.Error(w, target(r), 400)
		}
	})
	ts, err := a.TrailsIn(context.Background(), "700017004810")
	if err != nil || len(ts) != 1 || ts[0].Name != "observe-data" || !ts[0].Logging || strings.Join(ts[0].DataBuckets, ",") != "tf-state" {
		t.Fatal(ts, err)
	}
}
