// Package feeds is the collector's read-only AWS surface (O-4): the SQS queue the EventBridge rules deliver to, the
// S3 trail bucket, the CloudTrail, AWS Config and EventBridge describe calls the health checks read. It is a small
// client over the standard library (detect.AWS: SigV4, credentials minted per run from a web identity and never
// persisted). Every call here is a read except SQS ReceiveMessage and DeleteMessage, the consumer's own.
package feeds

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/providers/observe-aws/collector"
	"github.com/jfillman/clearance/providers/observe-aws/detect"
	"github.com/jfillman/clearance/providers/observe-aws/digest"
)

// Endpoints override the service URLs (tests, VPC endpoints). S3 is path-style when set.
type Endpoints struct{ S3, SQS, CloudTrail, Config, Events string }

// API is a region's clients over one credential.
type API struct {
	AWS *detect.AWS
	EP  Endpoints
}

func (a *API) region() string { return a.AWS.Region }

func (a *API) endpoint(override, service string) string {
	if override != "" {
		return strings.TrimRight(override, "/") + "/"
	}
	return "https://" + service + "." + a.region() + ".amazonaws.com/"
}

// jsonCall is an AWS JSON-protocol POST.
func (a *API) jsonCall(ctx context.Context, service, ep, target, ctype string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", ep, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("X-Amz-Target", target)
	b, _, err := a.AWS.Do(ctx, service, req, body)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s answer: %w", target, err)
	}
	return nil
}

// ---- S3 ---------------------------------------------------------------------------------------------------------

// S3 reads the trail bucket.
type S3 struct{ API *API }

func (s S3) url(bucket, key string, q url.Values) string {
	var base string
	if s.API.EP.S3 != "" {
		base = strings.TrimRight(s.API.EP.S3, "/") + "/" + bucket
	} else {
		base = "https://" + bucket + ".s3." + s.API.region() + ".amazonaws.com"
	}
	u := base + "/" + escapePath(key)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// escapePath is SigV4's once-encoded S3 path: everything but unreserved characters and the slash is %XX.
func escapePath(p string) string {
	var b strings.Builder
	for _, c := range []byte(p) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~', c == '/':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// List is every key under prefix (ListObjectsV2, followed to the end).
func (s S3) List(ctx context.Context, bucket, prefix string) ([]string, error) {
	var out []string
	token := ""
	for page := 0; page < 200; page++ {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", s.url(bucket, "", q), nil)
		if err != nil {
			return nil, err
		}
		b, _, err := s.API.AWS.Do(ctx, "s3", req, nil)
		if err != nil {
			return nil, err
		}
		var res struct {
			Truncated bool   `xml:"IsTruncated"`
			Next      string `xml:"NextContinuationToken"`
			Contents  []struct {
				Key string
			}
		}
		if err := xml.Unmarshal(b, &res); err != nil {
			return nil, fmt.Errorf("s3 ListObjectsV2 answer: %w", err)
		}
		for _, c := range res.Contents {
			out = append(out, c.Key)
		}
		if !res.Truncated {
			return out, nil
		}
		token = res.Next
	}
	return nil, errors.New("s3 ListObjectsV2: over 200 pages")
}

// Get is an object and its user metadata (names lowercased, without x-amz-meta-).
func (s S3) Get(ctx context.Context, bucket, key string) ([]byte, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.url(bucket, key, nil), nil)
	if err != nil {
		return nil, nil, err
	}
	// Asking for gzip ourselves stops Go's transport decompressing the CloudTrail objects (stored with
	// Content-Encoding: gzip); the collector decompresses (digest.Content, which also accepts a decompressed body).
	req.Header.Set("Accept-Encoding", "gzip")
	b, h, err := s.API.AWS.Do(ctx, "s3", req, nil)
	if err != nil {
		return nil, nil, err
	}
	meta := map[string]string{}
	for k, v := range h {
		if n, ok := strings.CutPrefix(strings.ToLower(k), "x-amz-meta-"); ok && len(v) > 0 {
			meta[n] = v[0]
		}
	}
	return b, meta, nil
}

// ---- SQS --------------------------------------------------------------------------------------------------------

// SQS is the collector's queue.
type SQS struct {
	API      *API
	QueueURL string
	Wait     int // long-poll seconds (default 20)
}

var _ collector.Queue = (*SQS)(nil)

// Receive long-polls for up to ten messages.
func (q *SQS) Receive(ctx context.Context) ([]collector.Message, error) {
	wait := q.Wait
	if wait == 0 {
		wait = 20
	}
	var out struct {
		Messages []struct{ MessageId, ReceiptHandle, Body string }
	}
	err := q.API.jsonCall(ctx, "sqs", q.API.endpoint(q.API.EP.SQS, "sqs"), "AmazonSQS.ReceiveMessage", "application/x-amz-json-1.0",
		map[string]any{"QueueUrl": q.QueueURL, "MaxNumberOfMessages": 10, "WaitTimeSeconds": wait}, &out)
	if err != nil {
		return nil, err
	}
	var ms []collector.Message
	for _, m := range out.Messages {
		ms = append(ms, collector.Message{ID: m.MessageId, Handle: m.ReceiptHandle, Body: m.Body})
	}
	return ms, nil
}

// Delete removes a processed message.
func (q *SQS) Delete(ctx context.Context, handle string) error {
	return q.API.jsonCall(ctx, "sqs", q.API.endpoint(q.API.EP.SQS, "sqs"), "AmazonSQS.DeleteMessage", "application/x-amz-json-1.0",
		map[string]any{"QueueUrl": q.QueueURL, "ReceiptHandle": handle}, nil)
}

// ---- CloudTrail -------------------------------------------------------------------------------------------------

const trailTarget = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101."

// PublicKeys finds a digest's public key by fingerprint with cloudtrail:ListPublicKeys, keeping what it learns.
type PublicKeys struct {
	API *API
	mu  sync.Mutex
	got map[string]*rsa.PublicKey
}

var _ digest.Keys = (*PublicKeys)(nil)

// PublicKey implements digest.Keys. AWS lists the keys whose private keys signed digests in a time range, so the
// range is the hours around the digest.
func (p *PublicKeys) PublicKey(fp string, at time.Time) (*rsa.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.got[fp]; ok {
		return k, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out struct {
		PublicKeyList []struct {
			Value       string
			Fingerprint string
		}
	}
	err := p.API.jsonCall(ctx, "cloudtrail", p.API.endpoint(p.API.EP.CloudTrail, "cloudtrail"), trailTarget+"ListPublicKeys", "application/x-amz-json-1.1",
		map[string]any{"StartTime": at.Add(-2 * time.Hour).Unix(), "EndTime": at.Add(2 * time.Hour).Unix()}, &out)
	if err != nil {
		return nil, err
	}
	if p.got == nil {
		p.got = map[string]*rsa.PublicKey{}
	}
	for _, k := range out.PublicKeyList {
		der, err := base64.StdEncoding.DecodeString(k.Value)
		if err != nil {
			continue
		}
		if pk, err := digest.ParsePublicKey(der); err == nil {
			p.got[k.Fingerprint] = pk
		}
	}
	if k, ok := p.got[fp]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("cloudtrail ListPublicKeys has no key with fingerprint %s", fp)
}

// Trails is the collector.Control.Trails reader: DescribeTrails, GetTrailStatus and GetEventSelectors per trail.
func (a *API) Trails(ctx context.Context) ([]collector.TrailState, error) {
	return a.trails(ctx, "")
}

// TrailsIn is Trails for the trails an account owns: an organization trail (and any other trail whose ARN names another
// account) is visible from a member account but cannot be read from it (GetTrailStatus is the owner's), so it is left
// to the reader in the account that owns it.
func (a *API) TrailsIn(ctx context.Context, account string) ([]collector.TrailState, error) {
	return a.trails(ctx, account)
}

func (a *API) trails(ctx context.Context, account string) ([]collector.TrailState, error) {
	ep := a.endpoint(a.EP.CloudTrail, "cloudtrail")
	var list struct {
		TrailList []struct {
			Name, TrailARN                          string
			IsMultiRegionTrail, IsOrganizationTrail bool
			LogFileValidationEnabled                bool
			HomeRegion                              string
		} `json:"trailList"`
	}
	if err := a.jsonCall(ctx, "cloudtrail", ep, trailTarget+"DescribeTrails", "application/x-amz-json-1.1", map[string]any{"includeShadowTrails": true}, &list); err != nil {
		return nil, err
	}
	var out []collector.TrailState
	for _, t := range list.TrailList {
		if account != "" && !strings.Contains(t.TrailARN, ":"+account+":") {
			continue
		}
		var st struct {
			IsLogging           bool
			LatestDeliveryError string
		}
		if err := a.jsonCall(ctx, "cloudtrail", ep, trailTarget+"GetTrailStatus", "application/x-amz-json-1.1", map[string]any{"Name": t.TrailARN}, &st); err != nil {
			return nil, fmt.Errorf("GetTrailStatus %s: %w", t.Name, err)
		}
		var sel struct {
			EventSelectors []struct {
				ReadWriteType           string
				IncludeManagementEvents bool
				DataResources           []struct {
					Type   string
					Values []string
				}
			}
			AdvancedEventSelectors []struct {
				FieldSelectors []struct {
					Field                                   string
					Equals, StartsWith, EndsWith, NotEquals []string
				}
			}
		}
		if err := a.jsonCall(ctx, "cloudtrail", ep, trailTarget+"GetEventSelectors", "application/x-amz-json-1.1", map[string]any{"TrailName": t.TrailARN}, &sel); err != nil {
			return nil, fmt.Errorf("GetEventSelectors %s: %w", t.Name, err)
		}
		ts := collector.TrailState{Name: t.Name, Logging: st.IsLogging, MultiRegion: t.IsMultiRegionTrail, Organization: t.IsOrganizationTrail,
			LogValidation: t.LogFileValidationEnabled, DeliveryError: st.LatestDeliveryError}
		for _, e := range sel.EventSelectors {
			if e.IncludeManagementEvents {
				ts.Management, ts.ReadWrite = true, e.ReadWriteType
			}
			for _, d := range e.DataResources {
				if d.Type == "AWS::S3::Object" {
					for _, v := range d.Values {
						ts.DataBuckets = append(ts.DataBuckets, bucketOf(v))
					}
				}
			}
		}
		for _, e := range sel.AdvancedEventSelectors {
			mgmt, data := false, false
			rw := "All"
			var buckets []string
			for _, f := range e.FieldSelectors {
				switch f.Field {
				case "eventCategory":
					mgmt = contains(f.Equals, "Management")
					data = contains(f.Equals, "Data")
				case "readOnly":
					switch {
					case contains(f.Equals, "false"):
						rw = "WriteOnly"
					case contains(f.Equals, "true"):
						rw = "ReadOnly"
					}
				case "resources.ARN":
					for _, v := range append(append([]string{}, f.Equals...), f.StartsWith...) {
						buckets = append(buckets, bucketOf(v))
					}
				}
			}
			if mgmt {
				ts.Management, ts.ReadWrite = true, rw
			}
			if data {
				ts.DataBuckets = append(ts.DataBuckets, buckets...)
			}
		}
		out = append(out, ts)
	}
	return out, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// bucketOf is the bucket of an S3 ARN (arn:aws:s3:::bucket/prefix).
func bucketOf(arn string) string {
	arn = strings.TrimPrefix(arn, "arn:aws:s3:::")
	if i := strings.Index(arn, "/"); i >= 0 {
		arn = arn[:i]
	}
	return arn
}

// ---- AWS Config and EventBridge ---------------------------------------------------------------------------------

// Recorders is collector.Control.Recorders: DescribeConfigurationRecorderStatus.
func (a *API) Recorders(ctx context.Context) ([]collector.RecorderState, error) {
	var out struct {
		Status []struct {
			Name             string `json:"name"`
			Recording        bool   `json:"recording"`
			LastStatus       string `json:"lastStatus"`
			LastErrorMessage string `json:"lastErrorMessage"`
		} `json:"ConfigurationRecordersStatus"`
	}
	if err := a.jsonCall(ctx, "config", a.endpoint(a.EP.Config, "config"), "StarlingDoveService.DescribeConfigurationRecorderStatus",
		"application/x-amz-json-1.1", map[string]any{}, &out); err != nil {
		return nil, err
	}
	var rs []collector.RecorderState
	for _, s := range out.Status {
		rs = append(rs, collector.RecorderState{Name: s.Name, Recording: s.Recording, LastStatus: s.LastStatus, Error: s.LastErrorMessage})
	}
	return rs, nil
}

// Rules is collector.Control.Rules: DescribeRule for each name; a rule that does not exist is state "".
func (a *API) Rules(ctx context.Context, names []string) ([]collector.RuleState, error) {
	var out []collector.RuleState
	for _, n := range names {
		var r struct{ Name, State string }
		err := a.jsonCall(ctx, "events", a.endpoint(a.EP.Events, "events"), "AWSEvents.DescribeRule", "application/x-amz-json-1.1", map[string]any{"Name": n}, &r)
		var se *detect.StatusError
		if errors.As(err, &se) && se.Status == 400 && strings.Contains(se.Body, "ResourceNotFoundException") {
			out = append(out, collector.RuleState{Name: n})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("DescribeRule %s: %w", n, err)
		}
		out = append(out, collector.RuleState{Name: n, State: r.State})
	}
	return out, nil
}
