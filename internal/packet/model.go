// Package packet is the evidence packet job (C-5): a date range and scope turned into one canonical JSON document, CSV
// projections of its sections and a PDF presentation of it, plus the originals an offline verifier (C-4) needs.
//
// The packet is built from the evidence chain alone (and the change and attestation rows the chain's records point
// at). It never invents a statement the records do not support: counts are recounted from the records, the
// "no exceptions" sentence is printed only beside a window in which every observation feed was verified healthy, and
// a scope with no collector says blind.
package packet

import (
	"encoding/json"
	"time"

	"github.com/jfillman/clearance/internal/observe"
)

// Schema names the packet's JSON shape.
const Schema = "clearance.packet/v1"

// Views.
const (
	ViewPacket   = "packet"   // the whole packet
	ViewFreeze   = "freeze"   // a change freeze: what changed or tried to change inside it
	ViewIncident = "incident" // an incident: the timeline of changes and exceptions in scope
)

// Params is what a packet is asked for.
type Params struct {
	From, To time.Time
	// Scopes are the observed scopes (an account, cluster or workspace) the coverage statement speaks for. Empty:
	// every scope the chain holds an observation or health record for.
	Scopes []string
	View   string
	// Title names a freeze or an incident (free text, printed in the header).
	Title string
	// App, Env and Cluster narrow the gate's records (changes, exceptions, break-glass) to one place; empty is all.
	App, Env, Cluster string
	// Mappings are "framework/version" keys; empty is every mapping the build carries.
	Mappings []string
	// Now is the time the packet is made at (the job's clock); the window never extends past it.
	Now time.Time
	// Version is the build that made it.
	Version string
	// LogKeys and WitnessPolicy are the ledger's public verification material, when the job was given it: the
	// checkpoint's signatures are checked with them and they are copied into the packet for the offline verifier.
	// Receipts are the prior acceptance receipts to carry (P-1 supplies them; none until it exists).
	Receipts      []Receipt
	LogKeys       []string // vkeys, the key in use first
	WitnessPolicy []byte
}

// Count is one counted state.
type Count struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// Packet is the packet's canonical document.
type Packet struct {
	Schema       string        `json:"schema"`
	Header       Header        `json:"header"`
	Coverage     Coverage      `json:"coverage_statement"`
	Assertions   []Control     `json:"control_assertions"`
	Changes      []Change      `json:"changes"`
	HumanCleared []HumanChange `json:"human_cleared_changes"`
	AIIdentities []AIIdentity  `json:"ai_identities"`
	Exceptions   Exceptions    `json:"exceptions"`
	Policy       []PolicyEvent `json:"policy_changes"`
	Verification Verification  `json:"verification"`
	Acceptances  Acceptances   `json:"acceptances"`
	// Timeline is the incident view's chronology of the changes and exceptions in scope (absent in the other views).
	Timeline []TimelineEntry `json:"timeline,omitempty"`
}

// TimelineEntry is one event of an incident timeline.
type TimelineEntry struct {
	TS     string `json:"ts"`
	Seq    int64  `json:"seq"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Header says what the packet is, who made it and what it covers.
type Header struct {
	View        string   `json:"view"`
	Title       string   `json:"title,omitempty"`
	GeneratedAt string   `json:"generated_at"`
	Producer    string   `json:"producer"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Scopes      []string `json:"observation_scopes"`
	Filter      Filter   `json:"filter"`
	Mappings    []string `json:"mappings"`
	Chain       ChainRef `json:"chain"`
	// Sections lists the sections this view carries; a view omits sections that do not answer its question, never
	// the coverage statement.
	Sections []string `json:"sections"`
}

// Filter is the gate scoping of a view.
type Filter struct {
	App     string `json:"app,omitempty"`
	Env     string `json:"env,omitempty"`
	Cluster string `json:"cluster,omitempty"`
}

// ChainRef is the chain the packet was read from: it was verified from genesis by the job.
type ChainRef struct {
	Count    int64  `json:"count"`
	Head     string `json:"head"`
	Verified bool   `json:"verified"`
	// FirstSeq and LastSeq bound the records the packet carries in full (every record between them, so the stored
	// prev_hash links can be rechecked); Window is how many of them carry a timestamp inside the window.
	FirstSeq int64 `json:"first_seq"`
	LastSeq  int64 `json:"last_seq"`
	Window   int   `json:"records_in_window"`
	Carried  int   `json:"records_carried"`
}

// Coverage is the coverage statement.
type Coverage struct {
	Total       int          `json:"total_records"`
	ByCoverage  []Count      `json:"by_coverage"`
	ByAssurance []Count      `json:"by_assurance"`
	Matrix      []MatrixRow  `json:"coverage_by_assurance"`
	Degraded    []Degraded   `json:"degraded_windows"`
	Scopes      []ScopeState `json:"observation_health"`
	// WindowVerified is true only when at least one scope was observed and every observed scope's feeds were healthy
	// for the whole window. Only then may the packet print that no exceptions were detected.
	WindowVerified bool   `json:"window_verified"`
	Text           string `json:"text"`
}

// MatrixRow is one coverage state's records by assurance state.
type MatrixRow struct {
	Coverage    string `json:"coverage"`
	Checkpoint  int    `json:"checkpointed"`
	Recorded    int    `json:"recorded_not_checkpointed"`
	NotRecorded int    `json:"not_recorded"`
	Total       int    `json:"total"`
}

// Degraded is a stretch of the window something could not be seen or decided: the core unreachable (a provider's
// outage report), a feed blind or degraded, or a break-glass window (decisions made outside the gate's view).
type Degraded struct {
	Kind    string `json:"kind"` // core-outage, feed-blind, feed-degraded, break-glass
	Scope   string `json:"scope,omitempty"`
	Source  string `json:"source,omitempty"`
	From    string `json:"from"`
	To      string `json:"to"`
	Seconds int64  `json:"seconds"`
	Reason  string `json:"reason,omitempty"`
	Seq     *int64 `json:"seq"`
}

// ScopeState is one observed scope's statement (O-1's coverage statement, built from the same records).
type ScopeState struct {
	Scope string `json:"scope"`
	// Collector is false when no feed has ever reported health for the scope: the scope is blind.
	Collector bool              `json:"collector"`
	Statement observe.Statement `json:"statement"`
	// Text is what the packet prints for the scope: the statement's words, or "blind" for a scope with no collector.
	Text string `json:"text"`
}

// Control is one framework control and its assertions.
type Control struct {
	Framework  string      `json:"framework"`
	Version    string      `json:"version"`
	Control    string      `json:"control"`
	Title      string      `json:"title"`
	Assertions []Assertion `json:"assertions"`
}

// Assertion is one tested statement. It rests on verified fields only: a record that supports it only through a field
// the writer merely claimed is listed under ClaimedOnly and does not count as support.
type Assertion struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Evaluator string `json:"evaluator"`
	// Status: met (every record in the population supports it), met-with-exceptions, claimed-only (the population rests on claimed fields), not-met, or not-evidenced (an
	// empty population, or a window whose feeds could not be verified, supports nothing).
	Status      string  `json:"status"`
	Population  int     `json:"population"`
	Supported   int     `json:"supported"`
	ClaimedOnly int     `json:"claimed_only"`
	Failed      int     `json:"failed"`
	Seqs        []int64 `json:"seqs,omitempty"` // the records behind the exceptions (first 50)
	Note        string  `json:"note,omitempty"`
}

// Subject is what a change is about: a rendered manifest tree (Argo CD) or a saved Terraform plan, side by side.
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	GitCommit string `json:"git_commit,omitempty"`
	// VariableSet is a Terraform plan's variable-set hash.
	VariableSet string `json:"variable_set,omitempty"`
}

// Reporter is who reported an outcome: the registered provider's name and conformance, or the core ("clearance")
// when it wrote the record itself.
type Reporter struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Conformance string `json:"conformance,omitempty"`
}

// Rollback is an outcome's claimed rollback.
type Rollback struct {
	Available *bool  `json:"available,omitempty"`
	Used      *bool  `json:"used,omitempty"`
	To        string `json:"to,omitempty"`
}

// Attestation is a change's signed attestation as the chain and the store record it.
type Attestation struct {
	Seq           int64  `json:"seq"`
	Digest        string `json:"digest"`
	Backend       string `json:"backend"`
	RekorLogIndex *int64 `json:"rekor_log_index,omitempty"`
	// Bundle is the file in the packet that holds the Sigstore bundle ("" when it could not be read).
	Bundle string `json:"bundle,omitempty"`
}

// Change is one change as the deploy.* records tell it.
type Change struct {
	ID      string   `json:"id"`
	App     string   `json:"app"`
	Env     string   `json:"env"`
	Place   string   `json:"place"` // the cluster, or a Terraform workspace
	Subject *Subject `json:"subject"`
	Tier    *int64   `json:"tier"`
	// OperationalClass is the I-1 class (availability, privilege, ...), printed only when the records carry it.
	OperationalClass []string `json:"operational_class,omitempty"`
	// ClassMapping is the version of the mapping that computed it (I-1, opclass/1).
	ClassMapping string       `json:"class_mapping,omitempty"`
	State        string       `json:"state"`
	FirstTS      string       `json:"first_ts"`
	Request      *int64       `json:"request_seq"`
	Clear        *int64       `json:"clear_seq"`
	ClearedBy    string       `json:"cleared_by,omitempty"`
	Outcome      *Outcome     `json:"outcome"`
	Failed       bool         `json:"failed"`
	Exceptions   []int64      `json:"exception_seqs,omitempty"`
	Attestation  *Attestation `json:"attestation,omitempty"`
	Seqs         []int64      `json:"seqs"`
	// ClearVerified: the clearing record's decision and tier were fields the core itself established.
	ClearVerified bool `json:"clear_verified"`
	// Agent is the agent that proposed the change, when one did (claimed by the registration).
	Agent string `json:"agent,omitempty"`
}

// Outcome is what a deployment reported and what was compared.
type Outcome struct {
	Seq      int64     `json:"seq"`
	TS       string    `json:"ts"`
	Applied  *bool     `json:"applied"`
	Matched  *bool     `json:"matched"`
	Verified bool      `json:"matched_verified"` // the core compared the digests itself
	Digest   string    `json:"digest,omitempty"`
	Health   string    `json:"health,omitempty"`
	Error    string    `json:"error,omitempty"`
	Reporter Reporter  `json:"reported_by"`
	Rollback *Rollback `json:"rollback,omitempty"`
}

// Approver is one approval as recorded.
type Approver struct {
	Person string `json:"person"`
	Sub    string `json:"sub"`
	Iss    string `json:"iss"`
	Role   string `json:"role"`
	Via    string `json:"via,omitempty"`
	At     string `json:"at"`
	// Kind is "person" when the approval route checked it (C-14), "" for an approval recorded before that check.
	Kind string `json:"kind"`
}

// HumanChange is a change a person cleared.
type HumanChange struct {
	Change    string     `json:"change"`
	App       string     `json:"app"`
	Env       string     `json:"env"`
	Tier      *int64     `json:"tier"`
	ClearSeq  int64      `json:"clear_seq"`
	Approvers []Approver `json:"approvers"`
	// Statement is token.ApproversStatement over the approvals: the line, or "" when the records cannot prove it.
	Statement string `json:"approvers_statement"`
	Printed   string `json:"printed"`
}

// AIIdentity is one agent seen in the window.
type AIIdentity struct {
	Agent         string   `json:"agent"`
	Principals    []string `json:"principals"`
	ModelVersions []string `json:"model_versions,omitempty"` // claimed by the runtime provider
	Records       int      `json:"records"`
	Allowed       int      `json:"allowed"`
	Denied        int      `json:"denied"`
	Changes       []string `json:"changes_proposed,omitempty"`
	Provenance    []string `json:"provenance_levels,omitempty"`
	FirstTS       string   `json:"first_ts"`
	LastTS        string   `json:"last_ts"`
}

// Exceptions is the exceptions section: one row per class.
type Exceptions struct {
	Count int `json:"count"`
	// Clean is the one sentence the packet may print for an empty list: set only when the window's feeds were
	// verified healthy and no row exists. Otherwise Unverified says why the empty list is not a clean one.
	Clean      string      `json:"clean_statement"`
	Unverified string      `json:"not_clean_reason,omitempty"`
	Rows       []Exception `json:"rows"`
	ByClass    []Count     `json:"by_class"`
}

// Exception classes, in the order the section prints them.
const (
	ClassOutOfBand   = "out-of-band"
	ClassBreakGlass  = "break-glass"
	ClassRefused     = "attempted-refused"
	ClassMonitoring  = "monitoring-protection"
	ClassDegraded    = "degraded-mode-auto-clear"
	ClassTokens      = "invalidated-token"
	ClassCorrelation = "provider-correlation-failure"
)

// ExceptionClasses are the classes, in print order. Every one is always listed in ByClass, even at zero.
var ExceptionClasses = []string{ClassOutOfBand, ClassBreakGlass, ClassRefused, ClassMonitoring, ClassDegraded, ClassTokens, ClassCorrelation}

// Exception is one exception row.
type Exception struct {
	Class   string `json:"class"`
	Seq     int64  `json:"seq"`
	TS      string `json:"ts"`
	Kind    string `json:"kind,omitempty"` // the exception's own kind (drift, untraced-apply, ...)
	Source  string `json:"source"`         // "gate" (a deploy.* record), "observation" (an observed event)
	Scope   string `json:"scope,omitempty"`
	Subject string `json:"subject,omitempty"` // the app and env, the resource or the token's change
	Actor   string `json:"actor,omitempty"`
	// Diff is what differed: expected and observed digests, the objects or addresses, or the operation observed.
	Diff             string   `json:"diff,omitempty"`
	Resolution       string   `json:"resolution"`
	Cause            string   `json:"cause,omitempty"`
	Detail           string   `json:"detail,omitempty"`
	Coverage         string   `json:"coverage,omitempty"`
	Window           string   `json:"break_glass_window,omitempty"`
	OperationalClass []string `json:"operational_class,omitempty"`
}

// PolicyEvent is a change in the policy in force or in the definitions a gate holds.
type PolicyEvent struct {
	Seq     int64  `json:"seq"`
	TS      string `json:"ts"`
	Kind    string `json:"kind"` // definition.load, definition.unload, definition.reject, policy-in-force
	Name    string `json:"name,omitempty"`
	Ref     string `json:"ref,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Acceptances is the signed acceptance receipts assurance recipients returned for earlier packets (package P-1:
// packet id, engagement, framework and mapping versions, checkpoint, verdict, per-control notes). P-1 does not exist
// yet, so Receipts is empty and the section says no receipt has been recorded; nothing is inferred from the chain.
// Later packets carry prior receipts here.
type Acceptances struct {
	// Status is "none-recorded" while there are no receipts, else "recorded".
	Status    string    `json:"status"`
	Statement string    `json:"statement"`
	Receipts  []Receipt `json:"receipts"`
}

// Receipt is one recipient's signed acceptance of a packet (the shape P-1 will fix; held as raw fields so a receipt is
// carried exactly as signed).
type Receipt struct {
	PacketID   string            `json:"packet_id"`
	Engagement string            `json:"engagement"`
	Mappings   []string          `json:"framework_mapping_versions"`
	Checkpoint string            `json:"checkpoint"`
	Verdict    string            `json:"verdict"`
	Notes      map[string]string `json:"control_notes,omitempty"` // by control
	Signed     json.RawMessage   `json:"signed,omitempty"`        // the signed receipt as received
}

// Verification says what an offline verifier (C-4) will find in the packet, and what it will not.
type Verification struct {
	Chain  string `json:"chain"`
	Ledger Ledger `json:"ledger"`
	// Files are the packet's files an offline verifier reads.
	Records             string   `json:"records_file"`
	Proofs              string   `json:"proofs_file,omitempty"`
	AttestationDir      string   `json:"attestations_dir,omitempty"`
	Attestations        int      `json:"attestations_carried"`
	AttestationsMissing []string `json:"attestations_missing,omitempty"`
	Statement           string   `json:"statement"`
	OSCAL               string   `json:"oscal_component_definition,omitempty"`
}

// Ledger is the evidence ledger as the packet found it.
type Ledger struct {
	// State: checkpointed (a witnessed checkpoint covers some of the packet's records), no-checkpoint (the store
	// holds none) or off (the store keeps no ledger).
	State string `json:"state"`
	// CheckpointFile, LogKeysFile and WitnessPolicyFile are the checkpoint note and the public keys it is checked with.
	Origin            string   `json:"origin,omitempty"`
	Size              int64    `json:"size,omitempty"`
	Root              string   `json:"root,omitempty"`
	CheckpointFile    string   `json:"checkpoint_file,omitempty"`
	LogKeysFile       string   `json:"log_keys_file,omitempty"`
	WitnessPolicyFile string   `json:"witness_policy_file,omitempty"`
	SignaturesChecked bool     `json:"signatures_checked"`
	Witnessed         bool     `json:"witnessed"`
	Cosigned          []string `json:"cosigned_by,omitempty"`
	Checkpointed      int      `json:"records_checkpointed"`
	NotCheckpointed   int      `json:"records_not_checkpointed"`
	ProofsCarried     int      `json:"proofs_carried"`
}
