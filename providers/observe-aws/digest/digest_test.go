package digest

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

const bucket = "trail-logs-111122223333"

type fixture struct {
	key  *rsa.PrivateKey
	keys KeyMap
	fp   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{key: k, fp: "fp-1", keys: KeyMap{"fp-1": &k.PublicKey}}
}

type signed struct {
	object  string
	content []byte
	sig     string
}

// digest builds and signs a digest covering logs, chained to prev.
func (f *fixture) digest(t *testing.T, hour int, logs map[string][]byte, prev *signed) signed {
	t.Helper()
	end := time.Date(2026, 11, 9, hour, 0, 0, 0, time.UTC)
	obj := "AWSLogs/111122223333/CloudTrail-Digest/us-east-1/2026/11/09/111122223333_CloudTrail-Digest_us-east-1_t_us-east-1_" + end.Format("20060102T150405Z") + ".json.gz"
	d := Digest{AWSAccountID: "111122223333", StartTime: end.Add(-time.Hour).Format(time.RFC3339), EndTime: end.Format(time.RFC3339),
		S3Bucket: bucket, S3Object: obj, Fingerprint: f.fp, SignatureAlgorithm: "SHA256withRSA"}
	prevSig := ""
	if prev != nil {
		d.PrevBucket, d.PrevObject, d.PrevHash, d.PrevHashAlgorithm, d.PrevSignature = bucket, prev.object, hexSum(prev.content), "SHA-256", prev.sig
		prevSig = prev.sig
	}
	for name, body := range logs {
		d.LogFiles = append(d.LogFiles, LogFile{S3Bucket: bucket, S3Object: name, HashValue: hexSum(body), HashAlgorithm: "SHA-256"})
	}
	content, _ := json.Marshal(d)
	sum := sha256.Sum256([]byte(SignedString(d.EndTime, bucket, obj, hexSum(content), prevSig)))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed{obj, content, hex.EncodeToString(sig)}
}

func TestDigestAndLogFileVerify(t *testing.T) {
	f := newFixture(t)
	log := []byte(`{"Records":[{"eventID":"e1"}]}`)
	d := f.digest(t, 10, map[string][]byte{"AWSLogs/x/log1.json.gz": log}, nil)
	v, fl := VerifyDigest(d.content, bucket, d.object, d.sig, "SHA256withRSA", f.keys)
	if fl != nil {
		t.Fatal(fl)
	}
	if fl := v.VerifyLogFile(bucket, "AWSLogs/x/log1.json.gz", log); fl != nil {
		t.Fatal(fl)
	}
}

func TestTamperedLogFileIsRejected(t *testing.T) {
	f := newFixture(t)
	log := []byte(`{"Records":[{"eventID":"e1"}]}`)
	d := f.digest(t, 10, map[string][]byte{"l1": log}, nil)
	v, fl := VerifyDigest(d.content, bucket, d.object, d.sig, "", f.keys)
	if fl != nil {
		t.Fatal(fl)
	}
	tampered := []byte(`{"Records":[{"eventID":"e2"}]}`)
	if fl := v.VerifyLogFile(bucket, "l1", tampered); fl == nil || fl.Reason != ReasonLogHash {
		t.Fatalf("a tampered log file must fail its hash: %v", fl)
	}
	if fl := v.VerifyLogFile(bucket, "unlisted", log); fl == nil || fl.Reason != ReasonLogMissing {
		t.Fatalf("a file the digest does not list must fail: %v", fl)
	}
}

func TestTamperedDigestIsRejected(t *testing.T) {
	f := newFixture(t)
	d := f.digest(t, 10, map[string][]byte{"l1": []byte("a")}, nil)
	// Change a log file's recorded hash inside the digest: the content hash, and so the signed string, changes.
	var m map[string]any
	_ = json.Unmarshal(d.content, &m)
	m["logFiles"].([]any)[0].(map[string]any)["hashValue"] = hexSum([]byte("forged"))
	forged, _ := json.Marshal(m)
	if _, fl := VerifyDigest(forged, bucket, d.object, d.sig, "", f.keys); fl == nil || fl.Reason != ReasonSignature {
		t.Fatalf("a tampered digest must fail its signature: %v", fl)
	}
	// A signature from another key.
	other := newFixture(t)
	od := other.digest(t, 10, map[string][]byte{"l1": []byte("a")}, nil)
	if _, fl := VerifyDigest(d.content, bucket, d.object, od.sig, "", f.keys); fl == nil || fl.Reason != ReasonSignature {
		t.Fatalf("a signature by another key must fail: %v", fl)
	}
	// An unknown fingerprint, a digest read from somewhere it does not name, a bad algorithm, no signature.
	if _, fl := VerifyDigest(d.content, bucket, d.object, d.sig, "", KeyMap{}); fl == nil || fl.Reason != ReasonKey {
		t.Fatal(fl)
	}
	if _, fl := VerifyDigest(d.content, bucket, "other/object", d.sig, "", f.keys); fl == nil || fl.Reason != ReasonMalformed {
		t.Fatal(fl)
	}
	if _, fl := VerifyDigest(d.content, bucket, d.object, d.sig, "MD5withRSA", f.keys); fl == nil || fl.Reason != ReasonAlgorithm {
		t.Fatal(fl)
	}
	if _, fl := VerifyDigest(d.content, bucket, d.object, "", "", f.keys); fl == nil || fl.Reason != ReasonSignature {
		t.Fatal(fl)
	}
	if _, fl := VerifyDigest([]byte("{"), bucket, d.object, d.sig, "", f.keys); fl == nil || fl.Reason != ReasonMalformed {
		t.Fatal(fl)
	}
}

func TestChainLinks(t *testing.T) {
	f := newFixture(t)
	d1 := f.digest(t, 10, nil, nil)
	d2 := f.digest(t, 11, nil, &d1)
	d3 := f.digest(t, 12, nil, &d2)
	v1, _ := VerifyDigest(d1.content, bucket, d1.object, d1.sig, "", f.keys)
	v2, fl := VerifyDigest(d2.content, bucket, d2.object, d2.sig, "", f.keys)
	v3, fl3 := VerifyDigest(d3.content, bucket, d3.object, d3.sig, "", f.keys)
	if v1 == nil || fl != nil || fl3 != nil {
		t.Fatal(fl, fl3)
	}
	if fl := VerifyLink(v1, v2); fl != nil {
		t.Fatal(fl)
	}
	if fl := VerifyLink(v2, v3); fl != nil {
		t.Fatal(fl)
	}
	// A missing digest: d3 does not follow d1.
	if fl := VerifyLink(v1, v3); fl == nil || fl.Reason != ReasonChain {
		t.Fatalf("a skipped digest must break the chain: %v", fl)
	}
	// A replaced previous digest (same key, different content): the recorded hash differs.
	forged := *v1
	forged.Hash = hexSum([]byte("forged"))
	if fl := VerifyLink(&forged, v2); fl == nil || fl.Reason != ReasonChain {
		t.Fatalf("a different previous file must break the chain: %v", fl)
	}
}

func TestGunzipAndParsePublicKey(t *testing.T) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte("hello"))
	zw.Close()
	if out, err := Gunzip(b.Bytes()); err != nil || string(out) != "hello" {
		t.Fatal(out, err)
	}
	if _, err := Gunzip([]byte("not gzip")); err == nil {
		t.Fatal("expected an error")
	}
	f := newFixture(t)
	der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if k, err := ParsePublicKey(der); err != nil || k.N.Cmp(f.key.N) != 0 {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey([]byte("junk")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestContentAcceptsGzipAndPlain(t *testing.T) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(`{"a":1}`))
	zw.Close()
	if out, err := Content(b.Bytes()); err != nil || string(out) != `{"a":1}` {
		t.Fatal(string(out), err)
	}
	if out, err := Content([]byte(`{"a":1}`)); err != nil || string(out) != `{"a":1}` {
		t.Fatal("a body the transport already decompressed is content:", string(out), err)
	}
	if _, err := Content(append([]byte{0x1f, 0x8b}, "truncated"...)); err == nil {
		t.Fatal("a corrupt gzip body is an error")
	}
	if _, err := Content(make([]byte, MaxFile+1)); err == nil {
		t.Fatal("plain content is bounded")
	}
}
