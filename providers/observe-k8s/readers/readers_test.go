package readers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/internal/vocab"
)

func lines(t *testing.T, name string) [][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	if len(out) == 0 {
		t.Fatalf("%s is empty", name)
	}
	return out
}

type sliceFetcher struct {
	pages [][][]byte
	i     int
	err   error
}

func (f *sliceFetcher) Fetch(_ context.Context, cursor string) ([][]byte, string, error) {
	if f.err != nil {
		return nil, cursor, f.err
	}
	if f.i >= len(f.pages) {
		return nil, cursor, nil
	}
	f.i++
	return f.pages[f.i-1], "page-" + string(rune('0'+f.i)), nil
}

type memSink struct {
	items [][]byte
	err   error
}

func (m *memSink) Append(p ...[]byte) error {
	if m.err != nil {
		return m.err
	}
	m.items = append(m.items, p...)
	return nil
}

type memCursor struct{ v string }

func (m *memCursor) Load() (string, error) { return m.v, nil }
func (m *memCursor) Save(s string) error   { m.v = s; return nil }

// Every source's recorded fixtures run through the same pipeline and come out the same way: a person's apply is
// out-of-band with the actor, a Secret write is recorded by name at Metadata with no body, a refusal is refused.
func TestEveryManagedSourceFeedsTheSameNormalizer(t *testing.T) {
	rs, err := pipeline.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		src  Source
		file string
		want map[string]string // resource -> coverage
	}{
		{EKS, "eks.jsonl", map[string]string{"ConfigMap/shop/web-config": "out-of-band-detected", "Secret/shop/db-creds": "out-of-band-detected", "Deployment/shop/web": "attempted-refused"}},
		{AKS, "aks.jsonl", map[string]string{"ConfigMap/shop/web-config": "out-of-band-detected", "Secret/shop/db-creds": "out-of-band-detected", "Deployment/shop/web": "attempted-refused"}},
		{GKE, "gke.jsonl", map[string]string{"ConfigMap/shop/web-config": "out-of-band-detected", "Secret/shop/db-creds": "out-of-band-detected", "Deployment/shop/web": "attempted-refused", "ClusterRoleBinding//root-ish": "out-of-band-detected"}},
	} {
		t.Run(c.src.Name, func(t *testing.T) {
			sink, cur := &memSink{}, &memCursor{}
			n, err := Poll(context.Background(), c.src, &sliceFetcher{pages: [][][]byte{lines(t, c.file)}}, sink, cur)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(c.want) || cur.v != "page-1" {
				t.Fatalf("queued %d events, cursor %q; want %d events and page-1 (entries of other categories or services are skipped)", n, cur.v, len(c.want))
			}
			p := pipeline.New(rs, nil, vocab.Default())
			got := map[string]string{}
			for _, it := range sink.items {
				a, disp, _, err := p.Process(pipeline.RawEvent{Provider: pipeline.Kubernetes, Scope: "prod-1", Raw: it})
				if err != nil || disp != pipeline.Assessed {
					t.Fatalf("%s: %v %v", it, disp, err)
				}
				got[a.Resource] = a.Coverage
				if a.Actor == "" {
					t.Errorf("%s has no actor", a.Resource)
				}
				if a.Resource == "Secret/shop/db-creds" && (a.AfterHash != "" || a.BeforeHash != "") {
					t.Errorf("a Secret event carried an object hash")
				}
			}
			for r, cov := range c.want {
				if got[r] != cov {
					t.Errorf("%s: %q, want %q (got %v)", r, got[r], cov, got)
				}
			}
		})
	}
}

// A managed cluster's own policy is not ours: if it records a Secret body, the cut is what keeps it out of the queue.
func TestSecretBodiesFromAManagedSourceNeverReachTheQueue(t *testing.T) {
	const v = "c3VwZXItc2VjcmV0LXZhbHVl"
	ev := map[string]any{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse", "auditID": "x1", "verb": "update", "stage": "ResponseComplete",
		"user": map[string]any{"username": "dana"}, "objectRef": map[string]any{"resource": "secrets", "namespace": "shop", "name": "db"},
		"requestObject": map[string]any{"kind": "Secret", "data": map[string]any{"password": v}}, "responseObject": map[string]any{"kind": "Secret", "data": map[string]any{"password": v}}}
	b, _ := json.Marshal(ev)
	msg, _ := json.Marshal(map[string]any{"message": string(b)})
	sink := &memSink{}
	if _, err := Poll(context.Background(), EKS, &sliceFetcher{pages: [][][]byte{{msg}}}, sink, &memCursor{}); err != nil {
		t.Fatal(err)
	}
	if len(sink.items) != 1 || bytes.Contains(sink.items[0], []byte(v)) || bytes.Contains(sink.items[0], []byte("password")) {
		t.Fatalf("%s", sink.items)
	}
}

// The cursor moves only after the events are in the queue: a failed append leaves it, so the page is read again.
func TestCursorMovesOnlyAfterTheAppend(t *testing.T) {
	cur := &memCursor{v: "start"}
	sink := &memSink{err: errors.New("disk full")}
	f := &sliceFetcher{pages: [][][]byte{lines(t, "eks.jsonl")}}
	if _, err := Poll(context.Background(), EKS, f, sink, cur); err == nil || cur.v != "start" {
		t.Fatalf("%v %q", err, cur.v)
	}
	sink.err = nil
	f.i = 0
	if n, err := Poll(context.Background(), EKS, f, sink, cur); err != nil || n != 3 || cur.v != "page-1" {
		t.Fatalf("%d %v %q", n, err, cur.v)
	}
	if _, err := Poll(context.Background(), EKS, &sliceFetcher{err: errors.New("throttled")}, sink, cur); err == nil || cur.v != "page-1" {
		t.Fatalf("a failed fetch must leave the cursor: %v %q", err, cur.v)
	}
}

func TestMalformedEntriesAreErrors(t *testing.T) {
	for name, c := range map[string]struct {
		parse func([]byte) ([][]byte, error)
		in    string
	}{
		"eks not json":          {ParseEKS, `not json`},
		"eks no message":        {ParseEKS, `{"timestamp":1}`},
		"eks message not audit": {ParseEKS, `{"message":"{\"a\":1}"}`},
		"aks no log":            {ParseAKS, `{"category":"kube-audit"}`},
		"gke bad method":        {ParseGKE, `{"insertId":"i","timestamp":"t","protoPayload":{"serviceName":"k8s.io","methodName":"nope","resourceName":"core/v1/pods"}}`},
		"gke bad resource":      {ParseGKE, `{"insertId":"i","timestamp":"t","protoPayload":{"serviceName":"k8s.io","methodName":"io.k8s.core.v1.pods.update","resourceName":"pods"}}`},
		"gke no principal":      {ParseGKE, `{"insertId":"i","timestamp":"t","protoPayload":{"serviceName":"k8s.io","methodName":"io.k8s.core.v1.pods.update","resourceName":"core/v1/pods/x"}}`},
	} {
		if _, err := c.parse([]byte(c.in)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if evs, err := ParseAKS([]byte(`{"category":"cloud-controller-manager","properties":{"log":"x"}}`)); err != nil || evs != nil {
		t.Fatalf("another category is skipped, not an error: %v %v", evs, err)
	}
}

func TestSourceLatenciesAreDeclaredAndDiffer(t *testing.T) {
	if EKS.Latency <= 0 || GKE.Latency <= 0 || AKS.Latency <= EKS.Latency {
		t.Fatalf("%v %v %v", EKS.Latency, GKE.Latency, AKS.Latency)
	}
	if _, ok := ByName("EKS"); !ok {
		t.Fatal("ByName")
	}
}

func FuzzParsers(f *testing.F) {
	for _, n := range []string{"eks.jsonl", "aks.jsonl", "gke.jsonl"} {
		b, _ := os.ReadFile(filepath.Join("testdata", n))
		for _, l := range bytes.Split(b, []byte("\n")) {
			f.Add(l)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range []func([]byte) ([][]byte, error){ParseEKS, ParseAKS, ParseGKE} {
			if evs, err := p(b); err == nil {
				for _, e := range evs {
					if !json.Valid(e) {
						t.Fatalf("not JSON: %s", e)
					}
				}
			}
		}
	})
}

func TestFileFetcherReadsNewLinesOnlyAndIgnoresAPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eks.jsonl")
	cur := FileCursor{Path: filepath.Join(dir, "cursor")}
	sink := &memSink{}
	poll := func() int {
		n, err := Poll(context.Background(), EKS, FileFetcher{Path: path}, sink, cur)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if poll() != 0 {
		t.Fatal("no file yet")
	}
	all := lines(t, "eks.jsonl")
	body := append(bytes.Join(all[:2], []byte("\n")), '\n')
	partial := all[2][:20] // the shipper is mid-write
	os.WriteFile(path, append(append([]byte{}, body...), partial...), 0o600)
	if n := poll(); n != 2 {
		t.Fatalf("read %d, want the 2 whole lines", n)
	}
	os.WriteFile(path, append(append([]byte{}, body...), append(all[2], '\n')...), 0o600)
	if n := poll(); n != 1 {
		t.Fatalf("read %d, want only the third", n)
	}
	if poll() != 0 {
		t.Fatal("nothing new")
	}
	if c, _ := cur.Load(); c != "3" {
		t.Fatalf("cursor %q", c)
	}
}
