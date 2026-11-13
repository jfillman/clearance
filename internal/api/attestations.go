package api

// Change history and attestations (C12, C13): one change's deploy.* records, the attestation list, the server-side
// verification of a stored attestation and the non-secret config a portal needs to link to Rekor and to print the
// offline verify command. Everything here is a read.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// AttestTrust is what the api trusts to verify a stored attestation: the public half of the static signing key, or
// the keyless trust root with the identity and issuer the certificate must name. All of it is public; none is key
// material beyond public keys. A nil *AttestTrust (nothing configured) serves no verification.
type AttestTrust struct {
	// Keys verify a static-key attestation (CLEARANCE_API_ATTEST_KEY: a PEM public key or the core's JWKS).
	Keys token.KeySet
	// Trust (a Sigstore TrustedRoot) or Roots with RekorKey verify a keyless one (CLEARANCE_API_ATTEST_TRUST_ROOT,
	// _REKOR_KEY), for Identity and Issuer (_IDENTITY, _ISSUER).
	Trust    *attest.TrustedRoot
	Roots    *x509.CertPool
	RekorKey *ecdsa.PublicKey
	Identity string
	Issuer   string
	// RekorURL is Rekor's public base URL (CLEARANCE_API_ATTEST_REKOR_URL), for "open in Rekor" links.
	RekorURL string
}

func (t *AttestTrust) options(subject string) attest.VerifyOptions {
	return attest.VerifyOptions{Subjects: []string{subject}, Keys: t.Keys, Trust: t.Trust, Roots: t.Roots,
		RekorKey: t.RekorKey, Identity: t.Identity, Issuer: t.Issuer}
}

func (t *AttestTrust) keyless() bool { return t != nil && (t.Trust != nil || t.Roots != nil) }
func (t *AttestTrust) static() bool  { return t != nil && len(t.Keys) > 0 }

// VerifyAnswer is GET /v1/clearances/{id}/attestation/verify: the stored bundle checked as `clearance attest
// verify` checks it, against the trust the api is configured with and the change's cleared digest. A portal says
// "verified" only when verified is true.
type VerifyAnswer struct {
	Verified  bool   `json:"verified"`
	CheckedAt string `json:"checked_at"`
	// Cached: the result of an earlier check of this same attestation (this replica remembers it until it restarts).
	Cached bool `json:"cached"`
	// Digest is the stored envelope's digest; Subject the digest the statement had to name (the change's cleared
	// tree, or its terraform plan), sha256:<hex>.
	Digest  string `json:"digest"`
	Subject string `json:"subject"`
	Mode    string `json:"mode,omitempty"` // static | keyless, from the bundle
	KeyID   string `json:"key_id,omitempty"`
	// Identity and Issuer are the keyless certificate's.
	Identity string       `json:"identity,omitempty"`
	Issuer   string       `json:"issuer,omitempty"`
	Rekor    RekorVerdict `json:"rekor"`
	Errors   []string     `json:"errors"`
}

// RekorVerdict is what the check made of the Rekor entry: its index and signed integration time, and whether the
// entry's signed timestamp checked against Rekor's key. verified is false with no entry, or with no Rekor key to
// check it with (a static attestation).
type RekorVerdict struct {
	LogIndex       *int64  `json:"log_index"`
	IntegratedTime *string `json:"integrated_time"`
	Verified       bool    `json:"verified"`
}

// VerificationBrief is what a list or a change shows of the last check: whether it passed and when.
type VerificationBrief struct {
	Verified  bool   `json:"verified"`
	CheckedAt string `json:"checked_at"`
}

// verifyCacheMax bounds the cache; when it is full the oldest half goes.
const verifyCacheMax = 5000

// verifier checks stored attestations and remembers the answers per change and envelope digest.
type verifier struct {
	trust *AttestTrust
	mu    sync.Mutex
	cache map[string]VerifyAnswer
}

func newVerifier(t *AttestTrust) *verifier {
	if t == nil || !(t.keyless() || t.static()) {
		return nil
	}
	return &verifier{trust: t, cache: map[string]VerifyAnswer{}}
}

func (v *verifier) key(changeID, digest string) string { return changeID + "\x00" + digest }

// brief is the cached verdict of the attestation, or nil when it was never checked here.
func (v *verifier) brief(changeID, digest string) *VerificationBrief {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if a, ok := v.cache[v.key(changeID, digest)]; ok {
		return &VerificationBrief{Verified: a.Verified, CheckedAt: a.CheckedAt}
	}
	return nil
}

func (v *verifier) put(changeID string, a VerifyAnswer) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= verifyCacheMax {
		all := make([]VerifyAnswer, 0, len(v.cache))
		keys := make([]string, 0, len(v.cache))
		for k, x := range v.cache {
			keys = append(keys, k)
			all = append(all, x)
		}
		idx := make([]int, len(keys))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(i, j int) bool { return all[idx[i]].CheckedAt < all[idx[j]].CheckedAt })
		for _, i := range idx[:len(idx)/2] {
			delete(v.cache, keys[i])
		}
	}
	v.cache[v.key(changeID, a.Digest)] = a
}

// clearedSubject is the digest the change's attestation must name: the terraform plan's for a plan change, else
// the tree's, as sha256:<hex> (the signer's subject: internal/attestor).
func clearedSubject(raw json.RawMessage) string {
	var c struct {
		TreeDigest string `json:"tree_digest"`
		Subject    *struct {
			Kind       string `json:"kind"`
			PlanDigest string `json:"planDigest"`
		} `json:"subject"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	d := c.TreeDigest
	if c.Subject != nil && c.Subject.Kind == gate.KindTerraformPlan {
		d = c.Subject.PlanDigest
	}
	if d == "" {
		return ""
	}
	return "sha256:" + strings.TrimPrefix(d, "sha256:")
}

// check verifies the stored attestation exactly as `clearance attest verify` does (attest.Verify with the
// configured trust and the change's cleared digest as the subject), and then holds the result to the change: the
// envelope's digest is the stored one, and the statement is about this change.
func (v *verifier) check(changeID, subject string, att store.Attestation, now time.Time) VerifyAnswer {
	ans := VerifyAnswer{CheckedAt: pycompat.ISO(now), Digest: att.Digest, Subject: subject, Errors: []string{}}
	fail := func(f string, a ...any) VerifyAnswer {
		ans.Verified = false
		ans.Errors = append(ans.Errors, fmt.Sprintf(f, a...))
		return ans
	}
	if subject == "" {
		return fail("the change records no cleared digest to check the attestation against")
	}
	res, err := attest.Verify(att.Bundle, v.trust.options(subject))
	if err != nil {
		return fail("%v", err)
	}
	ans.Mode, ans.KeyID, ans.Identity, ans.Issuer = res.Mode, res.KeyID, res.Identity, res.Issuer
	ans.Rekor.Verified = res.LogVerified
	if res.LogVerified && res.LogIndex != nil {
		ans.Rekor.LogIndex = res.LogIndex
		if b, err := attest.ParseBundle(att.Bundle); err == nil && len(b.VerificationMaterial.TlogEntries) == 1 {
			if n, err := strconv.ParseInt(b.VerificationMaterial.TlogEntries[0].IntegratedTime, 10, 64); err == nil {
				t := pycompat.ISO(time.Unix(n, 0).UTC())
				ans.Rekor.IntegratedTime = &t
			}
		}
	}
	if res.Digest != att.Digest {
		return fail("the stored bundle's envelope digest is %s, not the recorded %s", res.Digest, att.Digest)
	}
	if got := res.Statement.Predicate.Clearance.ID; got != changeID {
		return fail("the statement is about change %q, not %q", got, changeID)
	}
	ans.Verified = true
	return ans
}

// brief is the attestation's last check on this replica, if any.
func (s *Server) brief(a store.Attestation) *VerificationBrief {
	return s.verify.brief(a.ChangeID, a.Digest)
}

// attView is viewAttestation with the last check beside it.
func (s *Server) attView(a store.Attestation) AttestationView {
	view := viewAttestation(a)
	view.Verification = s.brief(a)
	return view
}

// getAttestationVerify is GET /v1/clearances/{id}/attestation/verify.
func (s *Server) getAttestationVerify(w http.ResponseWriter, r *http.Request, v *Viewer) {
	id := r.PathValue("id")
	raw, err := s.opt.Store.Change(r.Context(), id)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if raw == nil || !changeVisible(raw, v) {
		writeError(w, 404, "no such change")
		return
	}
	if s.verify == nil {
		writeError(w, 404, "this deployment has no attestation trust configured (CLEARANCE_API_ATTEST_KEY, or CLEARANCE_API_ATTEST_TRUST_ROOT with _IDENTITY and _ISSUER): nothing can be called verified here")
		return
	}
	att, err := s.opt.Store.Attestation(r.Context(), id)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if att == nil {
		writeError(w, 404, "this change has no attestation (it is not attested until a deploy reports its outcome)")
		return
	}
	subject := clearedSubject(raw)
	if cached, ok := s.cached(id, att.Digest, subject); ok {
		cached.Cached = true
		writeJSON(w, 200, cached)
		return
	}
	ans := s.verify.check(id, subject, *att, s.opt.Clock().UTC())
	s.verify.put(id, ans)
	writeJSON(w, 200, ans)
}

func (s *Server) cached(id, digest, subject string) (VerifyAnswer, bool) {
	s.verify.mu.Lock()
	defer s.verify.mu.Unlock()
	a, ok := s.verify.cache[s.verify.key(id, digest)]
	return a, ok && a.Subject == subject
}

// -- the change's records ------------------------------------------------------------------------------------------

// ChangeRecord is one record of a change's history: where it sits on the chain and the record as getEvidence serves
// it.
type ChangeRecord struct {
	Seq       int64   `json:"seq"`
	Hash      string  `json:"hash"`
	Tool      string  `json:"tool"`
	TS        string  `json:"ts"`
	Principal *string `json:"principal"`
	Record    Record  `json:"record"`
}

// ChangeRecordPage is GET /v1/clearances/{id}/records: the change's deploy.* records in chain order; next is the
// last item's seq when the page is full.
type ChangeRecordPage struct {
	Items []ChangeRecord `json:"items"`
	Next  *int64         `json:"next"`
}

// RecordRef names a record on the chain: the join key into GET /v1/evidence/{seq}.
type RecordRef struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

func (s *Server) listChangeRecords(w http.ResponseWriter, r *http.Request, v *Viewer) {
	id := r.PathValue("id")
	raw, err := s.opt.Store.Change(r.Context(), id)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if raw == nil || !changeVisible(raw, v) {
		writeError(w, 404, "no such change")
		return
	}
	q := query(r)
	limit, aerr := limitOf(q)
	if aerr != nil {
		aerr.write(w)
		return
	}
	var after *int64
	if a := q["after"]; a != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
		if err != nil {
			writeError(w, 400, "after is a seq")
			return
		}
		after = &n
	}
	recs, err := s.opt.Store.ChangeRecords(r.Context(), id, "", limit, after)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	page := ChangeRecordPage{Items: make([]ChangeRecord, 0, len(recs))}
	for _, rec := range recs {
		if !v.All() { // a deploy.exception's state_change, as an exception is read by a person
			rec = redactForPerson(rec)
		}
		rec = project(rec)
		seq, _ := seqOf(rec)
		it := ChangeRecord{Seq: seq, Record: rec}
		it.Hash, _ = rec["hash"].(string)
		it.Tool, _ = rec["tool"].(string)
		it.TS, _ = rec["ts"].(string)
		if p, ok := rec["principal"].(string); ok {
			it.Principal = &p
		}
		page.Items = append(page.Items, it)
	}
	if len(recs) == limit {
		if n, ok := seqOf(recs[len(recs)-1]); ok {
			page.Next = &n
		}
	}
	writeJSON(w, 200, page)
}

// requestRef is the change's first deploy.request record (the one POST /v1/clearances wrote when it registered
// the change), nil when it has none.
func (s *Server) requestRef(r *http.Request, id string) (*RecordRef, error) {
	recs, err := s.opt.Store.ChangeRecords(r.Context(), id, "deploy.request", 1, nil)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	seq, ok := seqOf(recs[0])
	hash, _ := recs[0]["hash"].(string)
	if !ok || hash == "" {
		return nil, nil
	}
	return &RecordRef{Seq: seq, Hash: hash}, nil
}

// -- the attestation list ------------------------------------------------------------------------------------------

// AttestationItem is one row of GET /v1/attestations: the attestation and the change it attests.
type AttestationItem struct {
	ChangeID string `json:"change_id"`
	App      string `json:"app"`
	Env      string `json:"env"`
	Cluster  string `json:"cluster"`
	// ReleaseID is the release the deploy named (the change's outcome.release); null when it named none.
	ReleaseID  *string `json:"release_id"`
	TreeDigest string  `json:"tree_digest"`
	// SignedAt is when the signer stored the attestation.
	SignedAt      string `json:"signed_at"`
	Digest        string `json:"digest"`
	Backend       string `json:"backend"`
	KeyID         string `json:"key_id,omitempty"`
	RekorLogIndex *int64 `json:"rekor_log_index"`
	RekorUUID     string `json:"rekor_uuid,omitempty"`
	// OutcomeSeq is the deploy.outcome it attests; RecordSeq the deploy.attestation record that carries its digest.
	OutcomeSeq   int64              `json:"outcome_seq"`
	RecordSeq    int64              `json:"record_seq"`
	Verification *VerificationBrief `json:"verification"`
}

// AttestationPage is a page of attestations, newest first: next is the last item's record_seq when the page is full.
type AttestationPage struct {
	Items []AttestationItem `json:"items"`
	Next  *int64            `json:"next"`
}

// parseWhen reads an ISO time the way isoTime accepts it (no offset is UTC).
func parseWhen(s string) (time.Time, bool) {
	s = strings.Replace(strings.Replace(s, " ", "T", 1), ",", ".", 1)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04", "2006-01-02T15", "2006-01-02",
		"2006-01-02T15:04:05.999999999-0700", "2006-01-02T15:04:05.999999999-07"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func (s *Server) listAttestations(w http.ResponseWriter, r *http.Request, v *Viewer) {
	q := query(r)
	limit, aerr := limitOf(q)
	if aerr != nil {
		aerr.write(w)
		return
	}
	f := AttestationFilter{App: strings.ToLower(q["app"]), Env: q["env"]}
	for _, p := range []struct {
		name string
		to   *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		raw := q[p.name]
		if raw == "" {
			continue
		}
		t, ok := parseWhen(raw)
		if !ok || !isoTime.MatchString(raw) {
			writeError(w, 400, p.name+" is an ISO time")
			return
		}
		*p.to = t
	}
	var after *int64
	if a := q["after"]; a != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
		if err != nil {
			writeError(w, 400, "after is a record_seq")
			return
		}
		after = &n
	}
	rows, err := s.opt.Store.Attestations(r.Context(), f, v, limit, after)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	page := AttestationPage{Items: make([]AttestationItem, 0, len(rows))}
	for _, row := range rows {
		var c struct {
			App        string `json:"app"`
			Env        string `json:"env"`
			Cluster    string `json:"cluster"`
			TreeDigest string `json:"tree_digest"`
			Outcome    *struct {
				Release string `json:"release"`
			} `json:"outcome"`
		}
		if err := json.Unmarshal(row.Change, &c); err != nil {
			s.readFailed(w, r, fmt.Errorf("api: a stored change: %w", err))
			return
		}
		a := row.Attestation
		it := AttestationItem{ChangeID: a.ChangeID, App: c.App, Env: c.Env, Cluster: c.Cluster, TreeDigest: c.TreeDigest,
			SignedAt: pycompat.ISO(a.CreatedAt), Digest: a.Digest, Backend: a.Backend, KeyID: a.KeyID,
			RekorLogIndex: a.RekorLogIndex, RekorUUID: a.RekorUUID, OutcomeSeq: a.OutcomeSeq, RecordSeq: a.RecordSeq,
			Verification: s.brief(a)}
		if c.Outcome != nil && c.Outcome.Release != "" {
			it.ReleaseID = &c.Outcome.Release
		}
		page.Items = append(page.Items, it)
	}
	if len(rows) == limit && limit > 0 {
		n := rows[len(rows)-1].Attestation.RecordSeq
		page.Next = &n
	}
	writeJSON(w, 200, page)
}

// withAttestations adds "attested" and "attestation" (the reference, null for none) to each listed change.
func (s *Server) withAttestations(r *http.Request, items []json.RawMessage) ([]json.RawMessage, error) {
	ids := make([]string, 0, len(items))
	for _, raw := range items {
		var c struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("api: a stored change: %w", err)
		}
		ids = append(ids, c.ID)
	}
	atts, err := s.opt.Store.AttestationsOf(r.Context(), ids)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(items))
	for i, raw := range items {
		var view any
		att, ok := atts[ids[i]]
		if ok {
			view = s.attView(att)
		}
		vb, err := json.Marshal(view)
		if err != nil {
			return nil, err
		}
		joined, err := addField(raw, "attested", []byte(strconv.FormatBool(ok)))
		if err == nil {
			joined, err = addField(joined, "attestation", vb)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, joined)
	}
	return out, nil
}

// -- the config ----------------------------------------------------------------------------------------------------

// AttestationConfig is GET /v1/attestation-config: the non-secret configuration a portal needs to link an
// attestation to Rekor and to print the offline verify command. Public keys only.
type AttestationConfig struct {
	// Verifiable: GET /v1/clearances/{id}/attestation/verify can check an attestation here. When false, a portal
	// must not call anything verified.
	Verifiable bool `json:"verifiable"`
	// Modes are the backends this api can verify: static and/or keyless.
	Modes []string `json:"modes"`
	// RekorURL is Rekor's public base URL ("" when none is configured); RekorEntryURL is the link to one entry, with
	// {log_index} to replace.
	RekorURL      string `json:"rekor_url"`
	RekorEntryURL string `json:"rekor_entry_url"`
	// Identity and Issuer are what a keyless certificate must name (the core's OIDC subject and issuer).
	Identity string `json:"identity,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	// KeyIDs are the static signing keys' ids (the public halves are configured here).
	KeyIDs []string `json:"key_ids"`
	// VerifyCommands are the offline check, with <tree-digest> and the trust-root file names to fill in.
	VerifyCommands []string `json:"verify_commands"`
}

func (s *Server) getAttestationConfig(w http.ResponseWriter, _ *http.Request, _ *Viewer) {
	cfg := AttestationConfig{Modes: []string{}, KeyIDs: []string{}, VerifyCommands: []string{}}
	t := s.opt.Attest
	if t != nil {
		cfg.RekorURL = t.RekorURL
		if t.RekorURL != "" {
			cfg.RekorEntryURL = strings.TrimRight(t.RekorURL, "/") + "/api/v1/log/entries?logIndex={log_index}"
		}
		if t.static() {
			cfg.Modes = append(cfg.Modes, "static")
			for k := range t.Keys {
				cfg.KeyIDs = append(cfg.KeyIDs, k)
			}
			sort.Strings(cfg.KeyIDs)
			cfg.VerifyCommands = append(cfg.VerifyCommands,
				"curl -s $CLEARANCE_API/v1/clearances/<id>/attestation | clearance attest verify --subject sha256:<tree-digest> --key <signing-key.pem|jwks.json>")
		}
		if t.keyless() {
			cfg.Modes = append(cfg.Modes, "keyless")
			cfg.Identity, cfg.Issuer = t.Identity, t.Issuer
			cfg.VerifyCommands = append(cfg.VerifyCommands, "curl -s $CLEARANCE_API/v1/clearances/<id>/attestation | clearance attest verify --subject sha256:<tree-digest> --trust-root <trusted-root.json> --identity '"+
				t.Identity+"' --issuer '"+t.Issuer+"'")
		}
	}
	cfg.Verifiable = s.verify != nil
	writeJSON(w, 200, cfg)
}
