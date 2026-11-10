// Package digesttest builds signed CloudTrail digests and log files for tests: a generated RSA key stands in for
// AWS's, and the signing string is the one package digest verifies.
package digesttest

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jfillman/clearance/providers/observe-aws/digest"
)

// Trail is a fake trail: a bucket, a key pair and the objects written so far.
type Trail struct {
	T       *testing.T
	Bucket  string
	Account string
	Region  string
	Prefix  string
	Key     *rsa.PrivateKey
	Keys    digest.KeyMap
	Objects map[string]Object
	prev    *Object
}

// Object is a stored object: the gzipped body and its S3 metadata.
type Object struct {
	Key     string
	Body    []byte // gzipped
	Content []byte // the uncompressed content
	Sig     string
	Algo    string
}

// New makes a trail for account in region, its digests under prefix (for example AWSLogs/o-abc/111122223333/).
func New(t *testing.T, bucket, prefix, account, region string) *Trail {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Trail{T: t, Bucket: bucket, Account: account, Region: region, Prefix: prefix, Key: k,
		Keys: digest.KeyMap{"fp-test": &k.PublicKey}, Objects: map[string]Object{}}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func hexSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// LogFile stores a log file of records, returning its key.
func (tr *Trail) LogFile(end time.Time, records ...json.RawMessage) string {
	content, _ := json.Marshal(map[string]any{"Records": records})
	key := fmt.Sprintf("%s%s/%s/%s_CloudTrail_%s_%s_x.json.gz", tr.Prefix+"CloudTrail/", tr.Region, end.Format("2006/01/02"), tr.Account, tr.Region, end.Format("20060102T1504Z"))
	tr.Objects[key] = Object{Key: key, Body: gz(content), Content: content}
	return key
}

// Digest signs and stores a digest for the hour ending at end, covering logs (keys from LogFile), chained to the
// previous digest unless skipPrev. It returns its key.
func (tr *Trail) Digest(end time.Time, logs []string, skipPrev bool) string {
	key := fmt.Sprintf("%sCloudTrail-Digest/%s/%s/%s_CloudTrail-Digest_%s_t_%s_%s.json.gz", tr.Prefix, tr.Region, end.Format("2006/01/02"),
		tr.Account, tr.Region, tr.Region, end.Format("20060102T150405Z"))
	d := digest.Digest{AWSAccountID: tr.Account, StartTime: end.Add(-time.Hour).Format(time.RFC3339), EndTime: end.Format(time.RFC3339),
		S3Bucket: tr.Bucket, S3Object: key, Fingerprint: "fp-test", SignatureAlgorithm: "SHA256withRSA"}
	prevSig := ""
	if tr.prev != nil && !skipPrev {
		d.PrevBucket, d.PrevObject, d.PrevHash, d.PrevHashAlgorithm, d.PrevSignature = tr.Bucket, tr.prev.Key, hexSum(tr.prev.Content), "SHA-256", tr.prev.Sig
		prevSig = tr.prev.Sig
	}
	for _, l := range logs {
		d.LogFiles = append(d.LogFiles, digest.LogFile{S3Bucket: tr.Bucket, S3Object: l, HashValue: hexSum(tr.Objects[l].Content), HashAlgorithm: "SHA-256"})
	}
	content, _ := json.Marshal(d)
	sum := sha256.Sum256([]byte(digest.SignedString(d.EndTime, tr.Bucket, key, hexSum(content), prevSig)))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tr.Key, crypto.SHA256, sum[:])
	if err != nil {
		tr.T.Fatal(err)
	}
	o := Object{Key: key, Body: gz(content), Content: content, Sig: hex.EncodeToString(sig), Algo: "SHA256withRSA"}
	tr.Objects[key] = o
	tr.prev = &o
	return key
}

// Tamper replaces an object's uncompressed content (a log file or a digest) and leaves the rest as it was.
func (tr *Trail) Tamper(key string, edit func([]byte) []byte) {
	o := tr.Objects[key]
	o.Content = edit(o.Content)
	o.Body = gz(o.Content)
	tr.Objects[key] = o
}
