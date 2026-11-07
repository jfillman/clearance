package detect

// A small AWS client over the standard library: SigV4 (the signing process AWS documents), S3 ListObjectVersions
// and CloudTrail LookupEvents. The repository takes no AWS SDK: three read calls do not need one. Credentials are
// never persisted: they come from the environment, or are minted per run by STS AssumeRoleWithWebIdentity from the
// pod's or runner's projected token, and live in memory for the run.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const maxAWSBody = 16 << 20

// Creds are AWS credentials. Token is empty for long-lived keys.
type Creds struct{ AccessKey, SecretKey, Token string }

// CredSource gives a run its credentials.
type CredSource func(ctx context.Context, hc *http.Client, region string) (Creds, error)

// EnvCreds reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN; without them, when
// AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE are set (IRSA, GitHub OIDC), it assumes the role with the token.
func EnvCreds(ctx context.Context, hc *http.Client, region string) (Creds, error) {
	if k, s := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); k != "" && s != "" {
		return Creds{k, s, os.Getenv("AWS_SESSION_TOKEN")}, nil
	}
	role, file := os.Getenv("AWS_ROLE_ARN"), os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if role == "" || file == "" {
		return Creds{}, errors.New("no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE")
	}
	tok, err := os.ReadFile(file)
	if err != nil {
		return Creds{}, fmt.Errorf("reading the web identity token: %w", err)
	}
	q := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {role},
		"RoleSessionName": {"terraform-detector"}, "DurationSeconds": {"900"},
		"WebIdentityToken": {strings.TrimSpace(string(tok))}}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://sts."+region+".amazonaws.com/", strings.NewReader(q.Encode()))
	if err != nil {
		return Creds{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, status, err := doAWS(hc, req)
	if err != nil {
		return Creds{}, err
	}
	if status != 200 {
		return Creds{}, fmt.Errorf("sts AssumeRoleWithWebIdentity: %d %s", status, clip(body))
	}
	var out struct {
		R struct {
			C struct{ AccessKeyId, SecretAccessKey, SessionToken string } `json:"Credentials"`
		} `json:"AssumeRoleWithWebIdentityResponse"`
		R2 struct {
			C struct{ AccessKeyId, SecretAccessKey, SessionToken string } `json:"Credentials"`
		} `json:"AssumeRoleWithWebIdentityResult"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Creds{}, fmt.Errorf("sts answer: %w", err)
	}
	c := out.R.C
	if c.AccessKeyId == "" {
		c = out.R2.C
	}
	if c.AccessKeyId == "" {
		return Creds{}, errors.New("sts answered without credentials")
	}
	return Creds{c.AccessKeyId, c.SecretAccessKey, c.SessionToken}, nil
}

func clip(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}

func doAWS(hc *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAWSBody+1))
	if err != nil {
		return nil, 0, err
	}
	if len(b) > maxAWSBody {
		return nil, 0, errors.New("the AWS answer is over the size cap")
	}
	return b, resp.StatusCode, nil
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// uriEncode is SigV4's encoding: unreserved characters stay, everything else is %XX (a slash stays in a path).
func uriEncode(s string, slash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !slash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Sign signs req (SigV4, header form) for service in region at now. The body is the payload that is hashed. The
// request's path must already be in its canonical (once-encoded) form, which Path/EscapedPath keep.
func Sign(req *http.Request, body []byte, c Creds, service, region string, now time.Time) {
	amz := now.UTC().Format("20060102T150405Z")
	day := amz[:8]
	req.Header.Set("X-Amz-Date", amz)
	if c.Token != "" {
		req.Header.Set("X-Amz-Security-Token", c.Token)
	}
	payload := hexSHA256(body)
	if service == "s3" {
		req.Header.Set("X-Amz-Content-Sha256", payload)
	}
	req.Header.Set("Host", req.URL.Host)
	var names []string
	for k := range req.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	var canon, signed strings.Builder
	for i, n := range names {
		v := req.Header.Get(n)
		if n == "host" {
			v = req.URL.Host
		}
		canon.WriteString(n + ":" + strings.Join(strings.Fields(v), " ") + "\n")
		if i > 0 {
			signed.WriteByte(';')
		}
		signed.WriteString(n)
	}
	q := req.URL.Query()
	var qs []string
	for k, vs := range q {
		for _, v := range vs {
			qs = append(qs, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	sort.Strings(qs)
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	creq := strings.Join([]string{req.Method, path, strings.Join(qs, "&"), canon.String(), signed.String(), payload}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hexSHA256([]byte(creq))
	k := hmacSHA256([]byte("AWS4"+c.SecretKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, scope, signed.String(), sig))
}

// AWS is the real StateBackend and Trail.
type AWS struct {
	Region string
	Creds  CredSource
	HTTP   *http.Client
	Now    func() time.Time
	// S3Endpoint and TrailEndpoint override the service URLs (tests, VPC endpoints). S3 is path-style when set.
	S3Endpoint, TrailEndpoint string
}

func (a *AWS) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (a *AWS) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *AWS) send(ctx context.Context, req *http.Request, body []byte, service string) ([]byte, error) {
	c, err := a.Creds(ctx, a.client(), a.Region)
	if err != nil {
		return nil, err
	}
	Sign(req, body, c, service, a.Region, a.now())
	b, status, err := doAWS(a.client(), req)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("%s %s: %d %s", service, req.Method, status, clip(b))
	}
	return b, nil
}

// StateVersion is one version of a state object.
type StateVersion struct {
	ID       string
	Modified time.Time
}

// ListVersions is s3:ListBucketVersions for exactly one key (GET /?versions&prefix=key, filtered to the key).
func (a *AWS) ListVersions(ctx context.Context, bucket, key string) ([]StateVersion, error) {
	var out []StateVersion
	marker, vmarker := "", ""
	for page := 0; page < 50; page++ {
		base := "https://" + bucket + ".s3." + a.Region + ".amazonaws.com/"
		if a.S3Endpoint != "" {
			base = strings.TrimRight(a.S3Endpoint, "/") + "/" + bucket + "/"
		}
		q := url.Values{"versions": {""}, "prefix": {key}}
		if marker != "" {
			q.Set("key-marker", marker)
			q.Set("version-id-marker", vmarker)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", base+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		b, err := a.send(ctx, req, nil, "s3")
		if err != nil {
			return nil, err
		}
		var res struct {
			Truncated bool   `xml:"IsTruncated"`
			NextKey   string `xml:"NextKeyMarker"`
			NextVer   string `xml:"NextVersionIdMarker"`
			Versions  []struct {
				Key, VersionId, LastModified string
			} `xml:"Version"`
		}
		if err := xml.Unmarshal(b, &res); err != nil {
			return nil, fmt.Errorf("s3 ListObjectVersions answer: %w", err)
		}
		for _, v := range res.Versions {
			if v.Key != key {
				continue
			}
			t, err := time.Parse(time.RFC3339, v.LastModified)
			if err != nil {
				return nil, fmt.Errorf("s3 version %s: bad LastModified", v.VersionId)
			}
			out = append(out, StateVersion{v.VersionId, t})
		}
		if !res.Truncated {
			return out, nil
		}
		marker, vmarker = res.NextKey, res.NextVer
	}
	return nil, errors.New("s3 ListObjectVersions: over 50 pages")
}

// PutEvent is a CloudTrail PutObject event on a state key.
type PutEvent struct {
	Time      time.Time
	Principal string
}

// StatePuts is cloudtrail:LookupEvents for PutObject in [from, to], kept to the bucket and key. The principal is
// the event's userIdentity ARN (an assumed role is named with its session, so a person behind a role shows).
func (a *AWS) StatePuts(ctx context.Context, bucket, key string, from, to time.Time) ([]PutEvent, error) {
	var out []PutEvent
	token := ""
	for page := 0; page < 50; page++ {
		in := map[string]any{"LookupAttributes": []map[string]string{{"AttributeKey": "EventName", "AttributeValue": "PutObject"}},
			"StartTime": from.Unix(), "EndTime": to.Unix(), "MaxResults": 50}
		if token != "" {
			in["NextToken"] = token
		}
		body, _ := json.Marshal(in)
		ep := a.TrailEndpoint
		if ep == "" {
			ep = "https://cloudtrail." + a.Region + ".amazonaws.com/"
		}
		req, err := http.NewRequestWithContext(ctx, "POST", ep, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents")
		b, err := a.send(ctx, req, body, "cloudtrail")
		if err != nil {
			return nil, err
		}
		var res struct {
			Events []struct {
				EventTime       float64
				CloudTrailEvent string
			}
			NextToken string
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return nil, fmt.Errorf("cloudtrail answer: %w", err)
		}
		for _, e := range res.Events {
			var ev struct {
				UserIdentity struct{ Arn, Type, PrincipalId string }
				Req          struct {
					Bucket string `json:"bucketName"`
					Key    string `json:"key"`
				} `json:"requestParameters"`
			}
			if json.Unmarshal([]byte(e.CloudTrailEvent), &ev) != nil || ev.Req.Bucket != bucket || ev.Req.Key != key {
				continue
			}
			who := ev.UserIdentity.Arn
			if who == "" {
				who = ev.UserIdentity.Type + ":" + ev.UserIdentity.PrincipalId
			}
			out = append(out, PutEvent{time.Unix(int64(e.EventTime), 0).UTC(), who})
		}
		if res.NextToken == "" {
			return out, nil
		}
		token = res.NextToken
	}
	return nil, errors.New("cloudtrail LookupEvents: over 50 pages")
}
