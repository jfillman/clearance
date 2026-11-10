// Package digest validates a CloudTrail trail's log-file integrity (O-4), the way AWS documents it: each hourly
// digest file carries an RSA signature (SHA256withRSA, in the S3 object's x-amz-meta-signature) over
//
//	<digestEndTime as yyyymmddThhmmssZ> \n <bucket>/<key> \n <hex sha256 of the digest file> \n <previous digest's signature>
//
// and lists the log files it covers with the sha256 of each one's uncompressed content, and the previous digest by
// its key, hash and signature. A log file is read for its events only after its digest verifies and its own hash
// matches; a file or a digest that fails is never extracted. The result is what an observation records as
// integrity.sourceVerified.
//
// This package reads nothing from AWS: callers fetch the objects (and the public key, by the digest's fingerprint,
// from cloudtrail:ListPublicKeys) and hand the bytes over. The signing string follows AWS's published description
// ("Validating CloudTrail log file integrity"); it is tested here against digests signed with a generated key, and it is
// not yet checked against a digest AWS signed (the rollout's first live validation does that).
package digest

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Failure reasons (Result.Reason), stable strings a health check can name.
const (
	ReasonSignature   = "digest-signature-invalid"
	ReasonKey         = "digest-public-key-unavailable"
	ReasonMalformed   = "digest-malformed"
	ReasonChain       = "digest-chain-broken"
	ReasonLogHash     = "log-file-hash-mismatch"
	ReasonLogMissing  = "log-file-not-in-digest"
	ReasonAlgorithm   = "digest-algorithm-unsupported"
	ReasonNotDigested = "log-file-not-yet-digested"
)

// MaxFile bounds one decompressed object.
const MaxFile = 64 << 20

// LogFile is one log file a digest covers.
type LogFile struct {
	S3Bucket      string `json:"s3Bucket"`
	S3Object      string `json:"s3Object"`
	HashValue     string `json:"hashValue"`
	HashAlgorithm string `json:"hashAlgorithm"`
	NewestEvent   string `json:"newestEventTime"`
	OldestEvent   string `json:"oldestEventTime"`
}

// Digest is a digest file's content.
type Digest struct {
	AWSAccountID       string    `json:"awsAccountId"`
	StartTime          string    `json:"digestStartTime"`
	EndTime            string    `json:"digestEndTime"`
	S3Bucket           string    `json:"digestS3Bucket"`
	S3Object           string    `json:"digestS3Object"`
	Fingerprint        string    `json:"digestPublicKeyFingerprint"`
	SignatureAlgorithm string    `json:"digestSignatureAlgorithm"`
	PrevBucket         string    `json:"previousDigestS3Bucket"`
	PrevObject         string    `json:"previousDigestS3Object"`
	PrevHash           string    `json:"previousDigestHashValue"`
	PrevHashAlgorithm  string    `json:"previousDigestHashAlgorithm"`
	PrevSignature      string    `json:"previousDigestSignature"`
	LogFiles           []LogFile `json:"logFiles"`
}

// Keys finds a digest's public key by the fingerprint the digest names.
type Keys interface {
	PublicKey(fingerprint string, at time.Time) (*rsa.PublicKey, error)
}

// KeyMap is a Keys held in memory (fingerprint to key).
type KeyMap map[string]*rsa.PublicKey

// PublicKey implements Keys.
func (m KeyMap) PublicKey(fp string, _ time.Time) (*rsa.PublicKey, error) {
	if k, ok := m[fp]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no public key with fingerprint %s", fp)
}

// ParsePublicKey reads the DER AWS returns from ListPublicKeys (an X.509 SubjectPublicKeyInfo; PKCS#1 is accepted).
func ParsePublicKey(der []byte) (*rsa.PublicKey, error) {
	if k, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			return rk, nil
		}
		return nil, errors.New("the public key is not RSA")
	}
	return x509.ParsePKCS1PublicKey(der)
}

// Gunzip decompresses an object, bounded.
func Gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, MaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(out) > MaxFile {
		return nil, errors.New("object is over the size cap")
	}
	return out, nil
}

// Content is an object's uncompressed content whether or not the transport already decompressed it. CloudTrail objects
// are stored gzipped with Content-Encoding: gzip, and an HTTP client that asked for gzip itself (Go's does, unless the
// request sets Accept-Encoding) hands back the decompressed body. A body with the gzip magic is decompressed (bounded);
// any other body is taken as already-decompressed content (bounded by MaxFile). Every hash AWS records (a log file's
// hashValue, previousDigestHashValue, the digest's signed hash) is over the uncompressed content, so it is the same
// bytes either way.
func Content(b []byte) ([]byte, error) {
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		return Gunzip(b)
	}
	if len(b) > MaxFile {
		return nil, errors.New("object is over the size cap")
	}
	return b, nil
}

// Verified is a digest that passed.
type Verified struct {
	Digest    Digest
	Key       string // bucket/object
	Hash      string // hex sha256 of the digest file's content
	Signature string // hex, from the object's metadata
	End       time.Time
	logs      map[string]LogFile
}

// Failure is a verification that failed: Reason is one of the Reason constants.
type Failure struct {
	Reason string
	Detail string
}

func (f *Failure) Error() string { return f.Reason + ": " + f.Detail }

func fail(reason, format string, a ...any) *Failure {
	return &Failure{reason, fmt.Sprintf(format, a...)}
}

func hexSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// SignedString is the data a digest's signature covers.
//
// endTime is the digest's digestEndTime exactly as the digest file writes it (e.g. 2026-11-10T21:33:00Z): AWS signs
// that string, not a reformatted time. Checked 2026-11-10 against a digest AWS signed (the organization trail of
// 700017004810, key fingerprint 93d8149d...): the compact yyyymmddThhmmssZ form does not verify; this one does.
func SignedString(endTime, bucket, object, contentHash, prevSignature string) string {
	if prevSignature == "" {
		prevSignature = "null"
	}
	return endTime + "\n" + bucket + "/" + object + "\n" + contentHash + "\n" + prevSignature
}

// VerifyDigest checks one digest file: content is its decompressed bytes, bucket and object are where it was read
// from, signatureHex and algorithm are its S3 object's metadata (x-amz-meta-signature, x-amz-meta-signature-algorithm).
// The digest must name itself (digestS3Bucket and digestS3Object) as where it was read from.
func VerifyDigest(content []byte, bucket, object, signatureHex, algorithm string, keys Keys) (*Verified, *Failure) {
	if algorithm != "" && !strings.EqualFold(algorithm, "SHA256withRSA") {
		return nil, fail(ReasonAlgorithm, "%q is not SHA256withRSA", algorithm)
	}
	var d Digest
	if err := json.Unmarshal(content, &d); err != nil {
		return nil, fail(ReasonMalformed, "the digest does not parse: %v", err)
	}
	end, err := time.Parse(time.RFC3339, d.EndTime)
	if err != nil || d.Fingerprint == "" {
		return nil, fail(ReasonMalformed, "the digest has no end time or public key fingerprint")
	}
	if d.S3Bucket != bucket || d.S3Object != object {
		return nil, fail(ReasonMalformed, "the digest names itself %s/%s but was read from %s/%s", d.S3Bucket, d.S3Object, bucket, object)
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) == 0 {
		return nil, fail(ReasonSignature, "the object carries no usable signature")
	}
	key, err := keys.PublicKey(d.Fingerprint, end)
	if err != nil {
		return nil, fail(ReasonKey, "%v", err)
	}
	hash := hexSum(content)
	signed := sha256.Sum256([]byte(SignedString(d.EndTime, bucket, object, hash, d.PrevSignature)))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, signed[:], sig); err != nil {
		return nil, fail(ReasonSignature, "the signature of %s/%s does not verify under key %s", bucket, object, d.Fingerprint)
	}
	v := &Verified{Digest: d, Key: bucket + "/" + object, Hash: hash, Signature: strings.ToLower(signatureHex), End: end,
		logs: map[string]LogFile{}}
	for _, l := range d.LogFiles {
		v.logs[l.S3Bucket+"/"+l.S3Object] = l
	}
	return v, nil
}

// VerifyLink checks that cur's previous-digest fields name prev: the same object, the hash of prev's content and
// prev's signature. Each digest signs the previous one's signature, so a verified link makes the chain.
func VerifyLink(prev, cur *Verified) *Failure {
	d := cur.Digest
	if d.PrevBucket+"/"+d.PrevObject != prev.Key {
		return fail(ReasonChain, "%s follows %s, not %s: a digest is missing", cur.Key, d.PrevBucket+"/"+d.PrevObject, prev.Key)
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(d.PrevHash)), []byte(prev.Hash)) != 1 {
		return fail(ReasonChain, "%s records a different hash for %s than the file read", cur.Key, prev.Key)
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(d.PrevSignature)), []byte(prev.Signature)) != 1 {
		return fail(ReasonChain, "%s records a different signature for %s than the file carries", cur.Key, prev.Key)
	}
	return nil
}

// Covers reports whether the verified digest lists the log file (bucket/object).
func (v *Verified) Covers(bucket, object string) (LogFile, bool) {
	l, ok := v.logs[bucket+"/"+object]
	return l, ok
}

// VerifyLogFile checks a log file's uncompressed content against the hash the verified digest lists for it.
// Extract nothing from a file this rejects.
func (v *Verified) VerifyLogFile(bucket, object string, content []byte) *Failure {
	l, ok := v.Covers(bucket, object)
	if !ok {
		return fail(ReasonLogMissing, "%s/%s is not listed in digest %s", bucket, object, v.Key)
	}
	if l.HashAlgorithm != "" && !strings.EqualFold(l.HashAlgorithm, "SHA-256") {
		return fail(ReasonAlgorithm, "log file hash algorithm %q", l.HashAlgorithm)
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(l.HashValue)), []byte(hexSum(content))) != 1 {
		return fail(ReasonLogHash, "%s/%s does not match the hash its digest records", bucket, object)
	}
	return nil
}
