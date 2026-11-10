package collector

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/providers/observe-aws/digest/digesttest"
)

type fakeObjects struct{ tr *digesttest.Trail }

func (f fakeObjects) List(_ context.Context, _, prefix string) ([]string, error) {
	var out []string
	for k := range f.tr.Objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f fakeObjects) Get(_ context.Context, _, key string) ([]byte, map[string]string, error) {
	o, ok := f.tr.Objects[key]
	if !ok {
		return nil, nil, &notFound{key}
	}
	return o.Body, map[string]string{"signature": o.Sig, "signature-algorithm": o.Algo}, nil
}

// decompressedObjects is S3 as the live collector saw it: the objects are stored gzipped with Content-Encoding: gzip,
// and the HTTP client handed back the decompressed body (the 2026-11-10 digest-malformed failures).
type decompressedObjects struct{ fakeObjects }

func (f decompressedObjects) Get(ctx context.Context, b, key string) ([]byte, map[string]string, error) {
	_, meta, err := f.fakeObjects.Get(ctx, b, key)
	if err != nil {
		return nil, nil, err
	}
	return f.tr.Objects[key].Content, meta, nil
}

// A body the transport already decompressed verifies exactly as a gzipped one: AWS hashes the uncompressed content.
func TestTrailAcceptsDecompressedBodies(t *testing.T) {
	r := newTrail(t)
	r.hour(1, "e1", "e2")
	r.hour(2, "e3")
	r.rd.Objects = decompressedObjects{fakeObjects{r.tr}}
	items, _, err := r.rd.Read(context.Background())
	if err != nil || len(items) != 3 {
		t.Fatal(len(items), err)
	}
	for _, it := range items {
		if !it.Verified {
			t.Fatalf("%+v", it)
		}
	}
	if f := r.rd.Failures(t0); len(f) != 0 {
		t.Fatalf("%v", f)
	}
}

// A decompressed body that was tampered still fails its hash: accepting plain content does not skip verification.
func TestDecompressedTamperedLogFileStillFails(t *testing.T) {
	r := newTrail(t)
	_, lk := r.hour(1, "e1")
	r.tr.Tamper(lk, func(b []byte) []byte { return append(b[:len(b)-1:len(b)-1], ' ', '}') })
	r.rd.Objects = decompressedObjects{fakeObjects{r.tr}}
	items, _, _ := r.rd.Read(context.Background())
	if len(items) != 0 || len(r.rd.Failures(t0)) != 1 || r.rd.Failures(t0)[0].Reason != "log-file-hash-mismatch" {
		t.Fatalf("%d %v", len(items), r.rd.Failures(t0))
	}
}

type notFound struct{ key string }

func (n *notFound) Error() string { return "not found: " + n.key }

func rec(id string) json.RawMessage { return consoleSG(id, t0).json() }

type trailRig struct {
	tr *digesttest.Trail
	rd *TrailReader
}

func newTrail(t *testing.T) *trailRig {
	tr := digesttest.New(t, "trail-logs", "AWSLogs/o-abc123/"+acct+"/", acct, "us-east-1")
	rd := &TrailReader{Objects: fakeObjects{tr}, Keys: tr.Keys, Bucket: "trail-logs", Prefix: tr.Prefix, Regions: []string{"us-east-1"},
		Since: t0, Now: func() time.Time { return t0.Add(10 * time.Hour) }}
	return &trailRig{tr, rd}
}

func (r *trailRig) hour(h int, ids ...string) (digestKey, logKey string) {
	var recs []json.RawMessage
	for _, id := range ids {
		recs = append(recs, rec(id))
	}
	end := t0.Add(time.Duration(h) * time.Hour)
	logKey = r.tr.LogFile(end, recs...)
	return r.tr.Digest(end, []string{logKey}, false), logKey
}

// The third Done-when: every observation from the S3 trail carries the digest-chain validation result.
func TestTrailObservationsCarryTheValidationResult(t *testing.T) {
	r := newTrail(t)
	r.hour(1, "e1", "e2")
	r.hour(2, "e3")
	items, more, err := r.rd.Read(context.Background())
	if err != nil || more || len(items) != 3 {
		t.Fatal(len(items), more, err)
	}
	for _, it := range items {
		if !it.Verified || it.Method != MethodDigestChain || it.Feed != FeedTrail {
			t.Fatalf("%+v", it)
		}
	}
	if len(r.rd.Failures(t0)) != 0 {
		t.Fatalf("%v", r.rd.Failures(t0))
	}
	if !r.rd.Newest().Equal(t0.Add(2 * time.Hour)) {
		t.Fatal(r.rd.Newest())
	}
	// Through the collector, the validation result is the observation's integrity.
	rg := newRig(t)
	for _, it := range items[:1] {
		if err := rg.c.Ingest(it); err != nil {
			t.Fatal(err)
		}
	}
	rg.settle()
	if o := rg.co.of("observation"); len(o) != 1 || o[0].Record.Integrity["sourceVerified"] != true || o[0].Record.Integrity["method"] != MethodDigestChain {
		t.Fatalf("%v", rg.co.kinds())
	}
	// And it is read once: the next batch has nothing.
	if items, _, _ := r.rd.Read(context.Background()); len(items) != 0 {
		t.Fatalf("a digest already read is not read again: %d", len(items))
	}
}

func TestTamperedLogFileIsNotExtracted(t *testing.T) {
	r := newTrail(t)
	_, log1 := r.hour(1, "e1")
	r.hour(2, "e2")
	r.tr.Tamper(log1, func(b []byte) []byte { return []byte(strings.Replace(string(b), "e1", "forged", 1)) })
	items, _, err := r.rd.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !strings.Contains(string(items[0].Raw), "e2") {
		t.Fatalf("only the untouched file is extracted: %d", len(items))
	}
	f := r.rd.Failures(t0)
	if len(f) != 1 || f[0].Reason != "log-file-hash-mismatch" || f[0].Key != log1 {
		t.Fatalf("%+v", f)
	}
}

func TestTamperedDigestIsNotExtractedAndItsSuccessorIsFlagged(t *testing.T) {
	r := newTrail(t)
	d1, _ := r.hour(1, "e1")
	r.hour(2, "e2")
	r.tr.Tamper(d1, func(b []byte) []byte {
		return []byte(strings.Replace(string(b), `"awsAccountId":"111122223333"`, `"awsAccountId":"999988887777"`, 1))
	})
	items, _, err := r.rd.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !strings.Contains(string(items[0].Raw), "e2") {
		t.Fatalf("nothing of a tampered digest is extracted: %d", len(items))
	}
	if items[0].Verified {
		t.Fatal("the next digest's link to the tampered one fails: its events are genuine but the chain is not whole")
	}
	reasons := map[string]bool{}
	for _, f := range r.rd.Failures(t0) {
		reasons[f.Reason] = true
	}
	if !reasons["digest-signature-invalid"] {
		t.Fatalf("%v", reasons)
	}
}

func TestMissingDigestBreaksTheChain(t *testing.T) {
	r := newTrail(t)
	r.hour(1, "e1")
	r.hour(2, "e2")
	// hour 3's digest is deleted by someone: hour 4 still verifies, but does not link to hour 2
	end3 := t0.Add(3 * time.Hour)
	log3 := r.tr.LogFile(end3, rec("e3"))
	d3 := r.tr.Digest(end3, []string{log3}, false)
	delete(r.tr.Objects, d3)
	r.hour(4, "e4")
	items, _, err := r.rd.Read(context.Background())
	if err != nil || len(items) != 3 {
		t.Fatal(len(items), err)
	}
	if items[2].Verified {
		t.Fatal("an event after a gap in the chain is not sourceVerified")
	}
	if f := r.rd.Failures(t0); len(f) != 1 || f[0].Reason != "digest-chain-broken" {
		t.Fatalf("%+v", f)
	}
}

func TestFirstDigestOfARunIsAnchoredToThePreviousOne(t *testing.T) {
	r := newTrail(t)
	r.hour(-2, "old") // before Since: the reader starts at hour 1 and must link back to it
	r.hour(1, "e1")
	items, _, err := r.rd.Read(context.Background())
	if err != nil || len(items) != 1 || !items[0].Verified {
		t.Fatal(len(items), err)
	}
}

func TestBatchesAreBounded(t *testing.T) {
	r := newTrail(t)
	for h := 1; h <= 5; h++ {
		r.hour(h, "e"+string(rune('0'+h)))
	}
	r.rd.MaxDigests = 2
	total := 0
	for i := 0; i < 10; i++ {
		items, more, err := r.rd.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		total += len(items)
		if len(items) > 2 {
			t.Fatalf("a batch is at most two digests: %d", len(items))
		}
		if !more {
			break
		}
	}
	if total != 5 {
		t.Fatal(total)
	}
}
