// Package statement is the verification statement (P-3): the packet's fourth derived view. A statement is cut from one
// published evidence packet and carries a public summary of it (period, scope as printed, counts by every coverage
// state, exceptions by class, observation health with its blind windows, the verification result, the receipts
// attached, a questionnaire-mapping block) and nothing recipient-specific: no record id, no resource, no person, no
// firm, no repository, no cluster. The subscriber's Clearance signs it (a DSSE envelope under the core's key), so a
// stranger holding the issuer's published keys checks it without Clearance.
//
// The package is small on purpose: the offline verifier (internal/verify) imports it, so it holds no store, no network
// and no clock. Build is the one function that derives a summary from a packet, and the verifier calls the same one to
// recompute it from the packet it is given: the issuer and the verifier cannot disagree about how a count is made.
package statement

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
)

// Schema is the statement's _type and schema name; PayloadType its DSSE payloadType.
const (
	Schema      = "clearance.statement/v1"
	PayloadType = "application/vnd.clearance.statement.v1+json"
	// StatusSchema and StatusPayloadType are the signed answer to "is this statement still current".
	StatusSchema      = "clearance.statement-status/v1"
	StatusPayloadType = "application/vnd.clearance.statement-status.v1+json"
)

// The profiles.
const (
	ProfileStandard = "standard"
	ProfileInsurer  = "insurer"
)

// Limits.
const (
	// MaxEnvelopeBytes caps a statement envelope the core issues and a verifier reads.
	MaxEnvelopeBytes = 256 << 10
	// MaxStatusBytes caps a status envelope.
	MaxStatusBytes = 16 << 10
	// MaxLabel and MaxPolicyVersion bound the two texts a subscriber chooses.
	MaxLabel         = 120
	MaxPolicyVersion = 64
	// MaxBlindWindows caps the blind windows a statement lists (the count is still the whole count).
	MaxBlindWindows = 200
	// MaxScopes caps the observed scopes a statement summarises.
	MaxScopes = 500
	// MaxUnresolved caps the unresolved exceptions the insurer profile lists. A packet with more is refused, not cut: the
	// profile lists each one.
	MaxUnresolved = 1000
	// MaxPacketJSON caps the packet.json a statement is derived from.
	MaxPacketJSON = 256 << 20
)

// The states of a statement.
const (
	StateValid      = "valid"
	StateSuperseded = "superseded"
	StateRevoked    = "revoked"
)

// IDBits is the entropy of a statement id: 128 random bits from crypto/rand. Nothing about the id is sequential, derived
// from the packet or guessable; one in 2^128 guesses finds a statement.
const IDBits = 128

var idPattern = regexp.MustCompile(`^st-[0-9a-f]{32}$`)

// ValidID reports whether s is the shape of a statement id: "st-" and 32 lowercase hex digits, exactly.
func ValidID(s string) bool { return len(s) == 35 && idPattern.MatchString(s) }

// NewID is a fresh statement id.
func NewID() (string, error) {
	var b [IDBits / 8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return "st-" + hex.EncodeToString(b[:]), nil
}

var (
	labelText   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._,:/()&+-]*$`)
	policyToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// ValidLabel reports whether s is a scope label a subscriber may print: 1 to MaxLabel characters of letters, digits,
// spaces and a few marks. No markup, no control character, no URL scheme separator.
func ValidLabel(s string) bool {
	return s != "" && len(s) <= MaxLabel && utf8.ValidString(s) && labelText.MatchString(s) && !strings.Contains(s, "://")
}

// ValidPolicyVersion reports whether s is a policy version a subscriber may print: 1 to MaxPolicyVersion letters,
// digits, dots, underscores and hyphens.
func ValidPolicyVersion(s string) bool {
	return s != "" && len(s) <= MaxPolicyVersion && policyToken.MatchString(s)
}

// Count is one counted state. Every state is listed, even at zero: a state left out would read as none.
type Count struct {
	State string `json:"state" contract:"required"`
	Count int    `json:"count" contract:"required"`
}

// Period is the window the statement speaks for.
type Period struct {
	From string `json:"from" contract:"required"`
	To   string `json:"to" contract:"required"`
}

// Scope is the scope as the subscriber prints it. Label is the subscriber's own words; Observed is how many observed
// scopes (an account, a cluster, a workspace) the counts speak for. Their names are in the recipient detail only.
type Scope struct {
	Label    string `json:"label" contract:"required"`
	Observed int    `json:"observed_scopes" contract:"required"`
}

// PacketRef names the one packet the statement was cut from.
type PacketRef struct {
	ID     string `json:"id" contract:"required"`
	Digest string `json:"digest" contract:"required"`
}

// CheckpointRef is the witnessed ledger checkpoint the packet's records stand under: its size and root. The log's origin
// (its name, which may be a host name) is in the packet, not here: not even a hash of it, which a guess could confirm.
type CheckpointRef struct {
	Size int64  `json:"size" contract:"required"`
	Root string `json:"root" contract:"required"`
}

// Cited are the records the counts rest on, as a count and one digest over their (seq, hash) pairs in seq order. The
// records and their inclusion proofs are the recipient detail; the digest binds the statement to exactly them.
type Cited struct {
	Count  int    `json:"count" contract:"required"`
	SHA256 string `json:"sha256" contract:"required"`
}

// ScopeHealth is one observed scope's three-part coverage, by position (the scope's name is not public).
type ScopeHealth struct {
	Index        int    `json:"index" contract:"required"`
	Collector    bool   `json:"collector" contract:"required"`
	State        string `json:"state" contract:"required"`
	Clean        bool   `json:"clean" contract:"required"`
	Cleared      int    `json:"cleared_and_verified" contract:"required"`
	Seen         int    `json:"seen_not_cleared" contract:"required"`
	BlindSeconds int64  `json:"could_not_see_seconds" contract:"required"`
}

// BlindWindow is a stretch of the period something could not be seen or decided.
type BlindWindow struct {
	Kind    string `json:"kind" contract:"required"`
	Index   int    `json:"scope_index" contract:"required"` // 0: not about one scope; else the ScopeHealth index
	From    string `json:"from" contract:"required"`
	To      string `json:"to" contract:"required"`
	Seconds int64  `json:"seconds" contract:"required"`
}

// Health is the observation-health summary.
type Health struct {
	// WindowVerified is true only when at least one scope was observed and every observed scope's feeds were healthy for
	// the whole period: the only case the statement may call the period clean.
	WindowVerified bool          `json:"window_verified" contract:"required"`
	Scopes         []ScopeHealth `json:"scopes" contract:"required"`
	BlindSeconds   int64         `json:"could_not_see_seconds" contract:"required"`
	BlindWindows   []BlindWindow `json:"blind_windows" contract:"required"`
	// BlindWindowsListed is false when there were more than MaxBlindWindows and the list is cut (the seconds are whole).
	BlindWindowsCut bool `json:"blind_windows_cut" contract:"required"`
}

// Exceptions are the period's exceptions by class (every class listed) and how many are unresolved.
type Exceptions struct {
	Total      int     `json:"total" contract:"required"`
	Unresolved int     `json:"unresolved" contract:"required"`
	ByClass    []Count `json:"by_class" contract:"required"`
}

// Ledger is the verification result the packet itself reported when it was made.
type Ledger struct {
	State           string `json:"state" contract:"required"` // checkpointed, no-checkpoint, off
	Checkpointed    int    `json:"records_checkpointed" contract:"required"`
	NotCheckpointed int    `json:"records_not_checkpointed" contract:"required"`
}

// Receipts are the acceptance receipts the packet carried (P-1), by verdict. The firms are in the recipient detail.
type Receipts struct {
	Count     int     `json:"count" contract:"required"`
	ByVerdict []Count `json:"by_verdict" contract:"required"`
}

// Summary is everything the public summary says that is a count.
type Summary struct {
	TotalRecords int        `json:"total_records" contract:"required"`
	ByCoverage   []Count    `json:"by_coverage" contract:"required"`
	Exceptions   Exceptions `json:"exceptions" contract:"required"`
	Health       Health     `json:"observation_health" contract:"required"`
	Ledger       Ledger     `json:"ledger" contract:"required"`
	Receipts     Receipts   `json:"receipts" contract:"required"`
}

// Unresolved is one unresolved exception as the insurer profile prints it: its class and its recorded disposition.
type Unresolved struct {
	Class       string `json:"class" contract:"required"`
	Disposition string `json:"disposition" contract:"required"`
}

// Insurer is the insurer profile's five figures.
type Insurer struct {
	// CriticalChanges is how many tier 3 changes were cleared in the period; WithTwoApprovers how many of them were
	// cleared by two distinct people (every approval kind person, C-14). SharePerMille (tenths of a percent, so no
	// floating point is signed) is null when there were none.
	CriticalChanges  int  `json:"critical_changes" contract:"required"`
	WithTwoApprovers int  `json:"critical_with_two_independent_approvers" contract:"required"`
	SharePerMille    *int `json:"critical_two_approver_share_per_mille"`
	// Unresolved lists each unresolved exception with its disposition.
	Unresolved []Unresolved `json:"unresolved_exceptions" contract:"required"`
	// Telemetry is each observed scope's share of the period the feeds could see, in tenths of a percent (1000 is all of it).
	Telemetry []TelemetryShare `json:"telemetry_coverage" contract:"required"`
	// Changes and AgentChanges are how many changes the packet lists and how many an agent proposed.
	Changes      int `json:"changes" contract:"required"`
	AgentChanges int `json:"agent_proposed_changes" contract:"required"`
	// AgentSharePerMille is null when there were no changes.
	AgentSharePerMille *int `json:"agent_share_per_mille"`
}

// TelemetryShare is one scope's telemetry coverage.
type TelemetryShare struct {
	Index    int `json:"scope_index" contract:"required"`
	PerMille int `json:"visible_per_mille" contract:"required"`
}

// Witness is what the issuer declares about the log's witnesses: the names of the ones it asserts it does not run. An
// issuer that declares none is saying no witness of its log is independent of it, which is the default: independence is
// asserted, never assumed. A verifier that supplies its own list of independent witnesses uses that and ignores this one,
// since who runs a witness is the verifier's to know, not the issuer's to say.
type Witness struct {
	Independent []string `json:"declared_independent" contract:"required"`
}

// MappingEntry is one line of the questionnaire-mapping block: an objective in a framework or questionnaire and what the
// statement is evidence for. It says "evidence for", never "compliant with".
type MappingEntry struct {
	Framework string `json:"framework" contract:"required"`
	Ref       string `json:"ref" contract:"required"`
	Objective string `json:"objective" contract:"required"`
	Evidence  string `json:"evidence" contract:"required"`
}

// Document is the signed payload.
type Document struct {
	Type          string         `json:"_type" contract:"required"`
	ID            string         `json:"id" contract:"required"`
	Issuer        string         `json:"issuer" contract:"required"`
	IssuedAt      string         `json:"issued_at" contract:"required"`
	Profile       string         `json:"profile" contract:"required"`
	Period        Period         `json:"period" contract:"required"`
	Scope         Scope          `json:"scope" contract:"required"`
	PolicyVersion string         `json:"policy_version" contract:"required"`
	Packet        PacketRef      `json:"packet" contract:"required"`
	Checkpoint    *CheckpointRef `json:"checkpoint"`
	Cited         Cited          `json:"cited_records" contract:"required"`
	Summary       Summary        `json:"summary" contract:"required"`
	Insurer       *Insurer       `json:"insurer,omitempty"`
	Witness       Witness        `json:"witnesses" contract:"required"`
	Mapping       []MappingEntry `json:"questionnaire_mapping" contract:"required"`
	MappingVer    string         `json:"questionnaire_mapping_version" contract:"required"`
	// Supersedes is the id of the statement this one corrects; "" for a first statement. The other direction
	// (supersededBy) is the core's current state, in the status, never in the signed document: a signed document cannot
	// learn of its successor.
	Supersedes string `json:"supersedes,omitempty"`
}

// Status is the signed answer to "is this statement still current", as of a time.
type Status struct {
	Type         string `json:"_type" contract:"required"`
	ID           string `json:"id" contract:"required"`
	State        string `json:"state" contract:"required"`
	SupersededBy string `json:"superseded_by,omitempty"`
	// SuccessorRevoked is true when the statement that replaced this one was itself revoked: neither is current.
	SuccessorRevoked bool   `json:"successor_revoked,omitempty"`
	RevokedAt        string `json:"revoked_at,omitempty"`
	AsOf             string `json:"as_of" contract:"required"`
}

// Check is what a Status must satisfy by itself.
func (s *Status) Check() error {
	switch {
	case s.Type != StatusSchema:
		return fmt.Errorf("the status _type is %q", s.Type)
	case !ValidID(s.ID):
		return errors.New("the status names no statement id")
	case s.State != StateValid && s.State != StateSuperseded && s.State != StateRevoked:
		return fmt.Errorf("the status state is %q", s.State)
	case s.State == StateSuperseded && !ValidID(s.SupersededBy):
		return errors.New("a superseded status names its successor")
	case s.AsOf == "":
		return errors.New("the status says nothing of when it is as of")
	}
	return nil
}

// Check is what a Document must satisfy by itself: the shape, not the truth.
func (d *Document) Check() error {
	switch {
	case d.Type != Schema:
		return fmt.Errorf("_type is %q, this reads %s", d.Type, Schema)
	case !ValidID(d.ID):
		return errors.New("id is not a statement id")
	case d.Profile != ProfileStandard && d.Profile != ProfileInsurer:
		return fmt.Errorf("profile is %q", d.Profile)
	case (d.Profile == ProfileInsurer) != (d.Insurer != nil):
		return errors.New("the insurer figures go with the insurer profile and only with it")
	case !ValidLabel(d.Scope.Label) || !ValidPolicyVersion(d.PolicyVersion):
		return errors.New("the scope label or the policy version is not printable text")
	case !validPacketID(d.Packet.ID) || len(d.Packet.Digest) != 64:
		return errors.New("packet names no packet")
	case d.Supersedes != "" && (!ValidID(d.Supersedes) || d.Supersedes == d.ID):
		return errors.New("supersedes is not another statement's id")
	case !ValidIssuer(d.Issuer):
		return errors.New("the issuer is not a public label or an https URL")
	}
	return d.checkSets()
}

var (
	blindKinds   = []string{"core-outage", "feed-blind", "feed-degraded", "break-glass"}
	scopeStates  = []string{"healthy", "degraded", "blind"}
	ledgerStates = []string{"checkpointed", "no-checkpoint", "off"}
	dispositions = []string{"none-recorded", "still-live", "revoked-not-recleared"}
)

func isRFC3339(s string) bool { _, err := time.Parse(time.RFC3339, s); return err == nil }

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}

// checkSets is the closed sets, the times, the hex and the list lengths: what a signed document is held to however it was made.
func (d *Document) checkSets() error {
	h := d.Summary.Health
	switch {
	case !isRFC3339(d.Period.From) || !isRFC3339(d.Period.To) || !isRFC3339(d.IssuedAt):
		return errors.New("a time is not RFC 3339")
	case !slices.Contains(ledgerStates, d.Summary.Ledger.State):
		return errors.New("the ledger state is not one this reads")
	case d.Checkpoint != nil && (d.Checkpoint.Size < 1 || !isHex64(d.Checkpoint.Root)):
		return errors.New("the checkpoint is not a size and a SHA-256 root")
	case !isHex64(d.Packet.Digest) || !isHex64(d.Cited.SHA256):
		return errors.New("a digest is not a SHA-256")
	case len(h.BlindWindows) > MaxBlindWindows || len(h.Scopes) > MaxScopes || d.Scope.Observed > MaxScopes:
		return errors.New("a list is longer than a statement carries")
	case d.Insurer != nil && (len(d.Insurer.Unresolved) > MaxUnresolved || len(d.Insurer.Telemetry) > MaxScopes):
		return errors.New("a list is longer than a statement carries")
	case len(d.Mapping) > 64 || len(d.Witness.Independent) > 32:
		return errors.New("a list is longer than a statement carries")
	}
	for _, w := range h.BlindWindows {
		if !slices.Contains(blindKinds, w.Kind) || !isRFC3339(w.From) || !isRFC3339(w.To) || w.Seconds < 0 || w.Index < 0 || w.Index > len(h.Scopes) {
			return errors.New("a blind window is not one this reads")
		}
	}
	for _, s := range h.Scopes {
		if !slices.Contains(scopeStates, s.State) {
			return errors.New("a scope's state is not one this reads")
		}
	}
	if d.Insurer != nil {
		for _, u := range d.Insurer.Unresolved {
			if !slices.Contains(ExceptionClasses, u.Class) || !slices.Contains(dispositions, u.Disposition) {
				return errors.New("an unresolved exception is not one this reads")
			}
		}
	}
	return nil
}

var labelIssuer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _-]{0,62}$`)

// ValidIssuer reports whether s may be printed as the issuer: a plain label (letters, digits, spaces, hyphens: no dot, so it
// is never a host name) or an https URL (no path but "/", no credentials, port, query or fragment) whose host is ASCII letters,
// digits and hyphens only (no IDNA folding: any other byte is refused), has at least two labels, a final label that is
// alphabetic and at least two characters, no all-numeric label and no 0x-prefixed label (so no IP literal in any spelling:
// 127.1, 0x7f.0.0.1, 0177.0.0.1, 10.1), and does not END in an internal suffix (.local, .internal, .lan, .localdomain,
// .home.arpa, .svc, .intranet, .corp, .invalid, .test, .localhost) or equal localhost. Suffixes are matched as whole trailing labels, so
// www.corp.acme.com is fine. A name that merely RESOLVES to an internal address (nip.io style) cannot be detected here; the issuer
// is a printed label and nothing fetches it. A bare host name with no dot is a label to this check: it cannot tell the operator's
// chosen label from one, which is why the docs tell the operator to choose a label that is not a host.
func ValidIssuer(s string) bool {
	if len(s) == 0 || len(s) > 200 || !utf8.ValidString(s) {
		return false
	}
	if !strings.Contains(s, "://") {
		return labelIssuer.MatchString(s)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" || strings.ContainsAny(s, "?#") ||
		(u.Path != "" && u.Path != "/") {
		return false
	}
	host := u.Hostname()
	for i := 0; i < len(host); i++ {
		if host[i] > 0x7e || host[i] < 0x2d {
			return false
		}
	}
	host = strings.ToLower(host)
	labels := strings.Split(host, ".")
	if len(labels) < 2 || host == "localhost" {
		return false
	}
	for _, l := range labels {
		if !hostLabel.MatchString(l) || strings.HasPrefix(l, "0x") || allDigits(l) {
			return false
		}
	}
	last := labels[len(labels)-1]
	if len(last) < 2 || !alphabetic(last) {
		return false
	}
	for _, bad := range []string{"local", "internal", "lan", "localdomain", "svc", "intranet", "corp", "invalid", "test", "localhost"} {
		if last == bad {
			return false
		}
	}
	return !strings.HasSuffix(host, ".home.arpa")
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func alphabetic(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return s != ""
}

func validPacketID(s string) bool {
	if len(s) != 35 || !strings.HasPrefix(s, "pk-") {
		return false
	}
	_, err := hex.DecodeString(s[3:])
	return err == nil
}

// Canonical is the document's canonical JSON: the bytes that are signed.
func (d *Document) Canonical() ([]byte, error) { return canonOf(d) }

// Canonical is the status's canonical JSON.
func (s *Status) Canonical() ([]byte, error) { return canonOf(s) }

func canonOf(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	p, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canon.Canonical(p)
}

// Digest is the SHA-256 of the document's canonical JSON.
func (d *Document) Digest() (string, error) {
	b, err := d.Canonical()
	if err != nil {
		return "", err
	}
	return canon.SHA256Hex(b), nil
}

// Parse reads a signed payload strictly: no unknown field, no trailing data, within MaxEnvelopeBytes.
func Parse(payload []byte) (*Document, error) {
	if len(payload) > MaxEnvelopeBytes {
		return nil, errors.New("the statement is too large")
	}
	var d Document
	if err := strict(payload, &d); err != nil {
		return nil, fmt.Errorf("not a %s document: %w", Schema, err)
	}
	if err := d.Check(); err != nil {
		return nil, err
	}
	return &d, nil
}

// ParseStatus reads a signed status payload strictly.
func ParseStatus(payload []byte) (*Status, error) {
	if len(payload) > MaxStatusBytes {
		return nil, errors.New("the status is too large")
	}
	var s Status
	if err := strict(payload, &s); err != nil {
		return nil, fmt.Errorf("not a %s document: %w", StatusSchema, err)
	}
	if err := s.Check(); err != nil {
		return nil, err
	}
	return &s, nil
}

func strict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// SeqHash is one cited record.
type SeqHash struct {
	Seq  int64
	Hash string
}

// CitedOf is the Cited block over records: their count and the SHA-256 of "<seq>:<hash>\n" in seq order.
func CitedOf(rs []SeqHash) Cited {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, func(a, b SeqHash) int {
		switch {
		case a.Seq < b.Seq:
			return -1
		case a.Seq > b.Seq:
			return 1
		}
		return 0
	})
	var b bytes.Buffer
	for _, r := range rs {
		fmt.Fprintf(&b, "%d:%s\n", r.Seq, r.Hash)
	}
	return Cited{Count: len(rs), SHA256: canon.SHA256Hex(b.Bytes())}
}

// RecordsOf reads evidence/records.jsonl and recomputes every record's hash, the way the verifier does (drop "hash",
// canonicalize, SHA-256). A line that is not a record, or whose stated hash is not the recomputed one, is an error: a
// statement is not cut from records that do not check.
func RecordsOf(jsonl []byte) ([]SeqHash, error) {
	var out []SeqHash
	if len(jsonl) == 0 {
		return nil, nil
	}
	for i, ln := range bytes.Split(bytes.TrimRight(jsonl, "\n"), []byte("\n")) {
		v, err := canon.Parse(ln)
		m, ok := v.(map[string]any)
		if err != nil || !ok {
			return nil, fmt.Errorf("records line %d is not a record", i+1)
		}
		seq, ok := intOf(m["seq"])
		stated, _ := m["hash"].(string)
		if !ok || len(stated) != 64 {
			return nil, fmt.Errorf("records line %d has no seq or no hash", i+1)
		}
		delete(m, "hash")
		cb, err := canon.Canonical(m)
		if err != nil {
			return nil, fmt.Errorf("records line %d cannot be canonicalized", i+1)
		}
		if got := canon.SHA256Hex(cb); got != stated {
			return nil, fmt.Errorf("records line %d (seq %d) does not hash to the hash it states", i+1, seq)
		}
		out = append(out, SeqHash{seq, stated})
	}
	return out, nil
}

func intOf(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		x, err := n.Int64()
		return x, err == nil
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// Coverage lists the coverage states, in the order the packet prints them.
func coverageStates() []string { return slices.Clone(evidence.Coverage) }
