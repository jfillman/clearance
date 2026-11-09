package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/providers/observe-aws/digest"
)

// Objects reads the trail bucket (feeds.S3).
type Objects interface {
	// List is every key under the prefix.
	List(ctx context.Context, bucket, prefix string) ([]string, error)
	// Get is an object's body and its metadata (lowercase names without the x-amz-meta- prefix: "signature",
	// "signature-algorithm").
	Get(ctx context.Context, bucket, key string) ([]byte, map[string]string, error)
}

// TrailFailure is a verification that failed, kept for the health record.
type TrailFailure struct {
	Key    string    `json:"key"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail"`
	At     time.Time `json:"at"`
}

// TrailReader reads the S3 trail in batches, verifying before it extracts:
//
//  1. a digest file: its RSA signature (digest.VerifyDigest) under the key its fingerprint names;
//  2. its link: it must name the previous digest by key, file hash and signature (digest.VerifyLink); the first digest
//     read in a run is linked to the previous digest object, fetched for the purpose;
//  3. each log file it lists: the sha256 of the uncompressed content must be the one the digest records, checked
//     before a record is parsed.
//
// A digest that fails its signature and a log file that fails its hash are never extracted. A digest that verifies but
// does not link to the one before it (a digest is missing or was replaced) is extracted with Verified=false: the
// events are genuine, the chain is not whole. Every failure is kept (Failures) and is what the health check
// "digests-validating" reads.
type TrailReader struct {
	Objects    Objects
	Keys       digest.Keys
	Bucket     string
	Prefix     string // the account's key prefix, ending in "/": AWSLogs/<account>/ or AWSLogs/<org>/<account>/
	Regions    []string
	Since      time.Time // where the first run starts (default: three hours back)
	MaxDigests int       // per Read: the batch size (default 24)
	Now        func() time.Time

	mu       sync.Mutex
	last     map[string]*digest.Verified // the last verified digest per region
	cursor   map[string]time.Time        // the end time of the last digest processed per region
	newest   time.Time                   // the end of the newest digest verified
	failures []TrailFailure
	verified int
}

func (t *TrailReader) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func digestEnd(key string) (time.Time, bool) {
	base := key[strings.LastIndex(key, "/")+1:]
	base = strings.TrimSuffix(base, ".json.gz")
	i := strings.LastIndex(base, "_")
	if i < 0 {
		return time.Time{}, false
	}
	tm, err := time.Parse("20060102T150405Z", base[i+1:])
	return tm, err == nil
}

func (t *TrailReader) fail(key, reason, detail string) {
	t.failures = append(t.failures, TrailFailure{Key: key, Reason: reason, Detail: detail, At: t.now()})
}

// Failures are the verification failures since the time.
func (t *TrailReader) Failures(since time.Time) []TrailFailure {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []TrailFailure
	for _, f := range t.failures {
		if !f.At.Before(since) {
			out = append(out, f)
		}
	}
	return out
}

// Newest is the end time of the newest digest that verified (zero before one has).
func (t *TrailReader) Newest() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.newest
}

// Read processes one batch of digests (the oldest unread, per region) and returns the events of every log file that
// verified. Call it again until it returns no items and no more digests are waiting (More).
func (t *TrailReader) Read(ctx context.Context) (items []*Item, more bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	max := t.MaxDigests
	if max <= 0 {
		max = 24
	}
	now := t.now()
	if t.cursor == nil {
		t.cursor, t.last = map[string]time.Time{}, map[string]*digest.Verified{}
	}
	since := t.Since
	if since.IsZero() {
		since = now.Add(-3 * time.Hour)
	}
	var errs []string
	for _, region := range t.Regions {
		from := t.cursor[region]
		if from.IsZero() {
			from = since
		}
		var keys []string
		for day := from.UTC().Truncate(24 * time.Hour); !day.After(now); day = day.AddDate(0, 0, 1) {
			ks, err := t.Objects.List(ctx, t.Bucket, fmt.Sprintf("%sCloudTrail-Digest/%s/%s/", t.Prefix, region, day.Format("2006/01/02")))
			if err != nil {
				errs = append(errs, fmt.Sprintf("listing %s digests of %s: %v", region, day.Format("2006-01-02"), err))
				break
			}
			keys = append(keys, ks...)
		}
		type dk struct {
			key string
			end time.Time
		}
		var todo []dk
		for _, k := range keys {
			if e, ok := digestEnd(k); ok && e.After(from) && !e.After(now) {
				todo = append(todo, dk{k, e})
			}
		}
		sort.Slice(todo, func(i, j int) bool { return todo[i].end.Before(todo[j].end) })
		if len(todo) > max {
			todo, more = todo[:max], true
		}
		for _, d := range todo {
			got, err := t.one(ctx, region, d.key, d.end)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", d.key, err))
				break // not advanced: the digest is read again next time
			}
			items = append(items, got...)
			t.cursor[region] = d.end
		}
	}
	if len(errs) > 0 {
		err = fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return items, more, err
}

// one verifies a digest and extracts its log files. A returned error is a failure to read (retry); a verification
// failure is recorded and is not an error.
func (t *TrailReader) one(ctx context.Context, region, key string, end time.Time) ([]*Item, error) {
	v, ok, err := t.fetchVerified(ctx, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // recorded; nothing of this digest is extracted
	}
	linked := true
	if prev := t.last[region]; prev != nil {
		if f := digest.VerifyLink(prev, v); f != nil {
			t.fail(key, f.Reason, f.Detail)
			linked = false
		}
	} else if v.Digest.PrevObject != "" {
		// the first digest of this run: anchor it to the digest before it
		pv, pok, perr := t.fetchVerified(ctx, v.Digest.PrevBucket+"\x00"+v.Digest.PrevObject)
		switch {
		case perr != nil || !pok:
			linked = false // the previous digest could not be read or did not verify: the failure is recorded by fetchVerified
		default:
			if f := digest.VerifyLink(pv, v); f != nil {
				t.fail(key, f.Reason, f.Detail)
				linked = false
			}
		}
	}
	t.last[region] = v
	if end.After(t.newest) {
		t.newest = end
	}
	var items []*Item
	for _, l := range v.Digest.LogFiles {
		body, _, err := t.Objects.Get(ctx, l.S3Bucket, l.S3Object)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", l.S3Object, err)
		}
		content, err := digest.Gunzip(body)
		if err != nil {
			t.fail(l.S3Object, digest.ReasonLogHash, "the log file does not decompress: "+err.Error())
			continue
		}
		if f := v.VerifyLogFile(l.S3Bucket, l.S3Object, content); f != nil {
			t.fail(l.S3Object, f.Reason, f.Detail)
			continue // a file that fails its hash is not extracted
		}
		var doc struct {
			Records []json.RawMessage `json:"Records"`
		}
		if err := json.Unmarshal(content, &doc); err != nil {
			t.fail(l.S3Object, digest.ReasonMalformed, "the verified log file is not CloudTrail JSON: "+err.Error())
			continue
		}
		t.verified += len(doc.Records)
		for _, r := range doc.Records {
			items = append(items, &Item{Feed: FeedTrail, Raw: r, Verified: linked, Method: MethodDigestChain, Received: t.now()})
		}
	}
	return items, nil
}

// fetchVerified reads a digest and verifies its signature. A key of the form "bucket\x00object" reads an object in a
// named bucket (the previous digest); otherwise the trail's bucket.
func (t *TrailReader) fetchVerified(ctx context.Context, key string) (*digest.Verified, bool, error) {
	bucket := t.Bucket
	if b, o, ok := strings.Cut(key, "\x00"); ok {
		bucket, key = b, o
	}
	body, meta, err := t.Objects.Get(ctx, bucket, key)
	if err != nil {
		return nil, false, fmt.Errorf("reading digest: %w", err)
	}
	content, err := digest.Gunzip(body)
	if err != nil {
		t.fail(key, digest.ReasonMalformed, "the digest does not decompress: "+err.Error())
		return nil, false, nil
	}
	v, f := digest.VerifyDigest(content, bucket, key, meta["signature"], meta["signature-algorithm"], t.Keys)
	if f != nil {
		t.fail(key, f.Reason, f.Detail)
		return nil, false, nil
	}
	return v, true, nil
}
