package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/token"
)

// The seven checks of a verification statement (P-3), in order. The hosted page prints exactly these.
var StatementChecks = [7]string{
	"1. signed by the issuer's Clearance identity",
	"2. the signature is valid and the signed document is the one read",
	"3. every cited record has an inclusion proof under a checkpoint",
	"4. the checkpoint is countersigned by a witness Clearance does not run",
	"5. the counts recompute from the cited records",
	"6. exceptions and observation health are present and match",
	"7. not superseded or revoked",
}

// NotWitnessed: the checkpoint is countersigned, and only by witnesses the issuer runs. Not a pass of the independent-witness
// check, and not a failure: the lab's honest answer until a witness the issuer does not run has seen the log.
const NotWitnessed Status = "NOT INDEPENDENTLY WITNESSED"

// Live is the core's current state of a statement, as the core itself reports it (the hosted page): its state and when
// that was read.
type Live struct {
	State        string
	SupersededBy string
	RevokedAt    string
	AsOf         time.Time
}

// StatementOptions are the trust inputs of a statement verification, all of them bytes the caller already read.
type StatementOptions struct {
	// Options carries the log keys, the witness policy and the recipient keys, as for a packet.
	Options
	// Keys are the issuer's public keys (GET /v1/keys: a JWKS, or PEM), and Issuer the issuer's name they are for. A
	// statement's own claim of who issued it is not trust: without Keys checks 1 and 2 are NOT CHECKED, and without Issuer
	// check 1 is SELF-VOUCHED (the keys are yours, the name is the statement's own).
	Keys    token.KeySet
	KeysSrc string
	Issuer  string
	// IndependentWitnesses are the names of the witnesses YOU know the issuer does not run. Check 4 passes only on a
	// countersignature by one of these. Without any, the statement's own declaration is used and the check is
	// SELF-VOUCHED at best: who runs a witness is the issuer's claim until you supply it.
	IndependentWitnesses []string
	// PacketDir is the packet the statement was cut from (recipient detail), or PacketFiles the same in memory (the hosted
	// page, which holds the packet). With neither, checks 3 to 6 are NOT CHECKED.
	PacketDir   string
	PacketFiles map[string][]byte
	// Status is a signed status envelope (GET /s/{id}/status.json) and StatusMaxAge how old it may be (default 24h), or Live
	// the core's own answer. With neither, check 7 is NOT CHECKED.
	Status       []byte
	StatusSrc    string
	StatusMaxAge time.Duration
	Live         *Live
}

// DefaultStatusMaxAge is how old a signed status may be before check 7 will not rest on it.
const DefaultStatusMaxAge = 24 * time.Hour

// VerifyStatementFile is `clearance verify --statement <file>`.
func VerifyStatementFile(file string, so StatementOptions) *Report {
	f, err := os.Open(file)
	if err != nil {
		return failedStatement(file, "the statement cannot be read: "+err.Error())
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, statement.MaxEnvelopeBytes+1))
	if err != nil || len(raw) > statement.MaxEnvelopeBytes {
		return failedStatement(file, fmt.Sprintf("the statement cannot be read, or is over %d bytes", statement.MaxEnvelopeBytes))
	}
	return VerifyStatement(raw, file, so)
}

func failedStatement(name, detail string) *Report {
	r := &Report{Packet: name}
	r.add(Check{Name: StatementChecks[0], Status: Fail, Detail: detail})
	return r
}

// VerifyStatement runs the seven checks on a signed statement envelope. name is only what the report calls it. A check whose
// input is missing is NOT CHECKED, never a pass; nothing is decided on the statement until its signature has verified; the
// packet checks are the packet verifier's own (the same functions `clearance verify <packet>` runs), rolled up.
func VerifyStatement(envelope []byte, name string, so StatementOptions) *Report {
	rep := &Report{Packet: name}
	if so.Now == nil {
		so.Now = time.Now
	}
	var checks [7]Check
	for i := range checks {
		checks[i] = Check{Name: StatementChecks[i]}
	}
	defer func() { rep.Checks = checks[:] }()

	rep.Inputs = []Input{
		{"issuer keys", srcOf(len(so.Keys) > 0, so.KeysSrc)},
		{"issuer name", srcOf(so.Issuer != "", so.Issuer)},
		{"log keys", srcOf(len(so.LogKeys) > 0, so.LogKeysSrc)},
		{"witness policy", srcOf(len(so.WitnessPolicy) > 0, so.WitnessPolicySrc)},
		{"independent witnesses", srcOf(len(so.IndependentWitnesses) > 0, fmt.Sprint(len(so.IndependentWitnesses))+" name(s)")},
	}
	switch {
	case so.PacketDir != "":
		rep.Inputs = append(rep.Inputs, Input{"packet (recipient detail)", "supplied by you (" + so.PacketDir + ")"})
	case so.PacketFiles != nil:
		rep.Inputs = append(rep.Inputs, Input{"packet (recipient detail)", "held by the core that issued the statement"})
	default:
		rep.Inputs = append(rep.Inputs, Input{"packet (recipient detail)", "none"})
	}
	switch {
	case so.Live != nil:
		rep.Inputs = append(rep.Inputs, Input{"current state", "the core's own, as of " + so.Live.AsOf.UTC().Format(time.RFC3339)})
	case len(so.Status) > 0:
		rep.Inputs = append(rep.Inputs, Input{"current state", "supplied by you (" + so.StatusSrc + ")"})
	default:
		rep.Inputs = append(rep.Inputs, Input{"current state", "none"})
	}

	doc := c1c2(&checks, envelope, so)
	if doc == nil {
		for i := 2; i < 6; i++ {
			checks[i].Status, checks[i].Detail = NotChecked, "the statement's signature was not verified, so nothing it says is checked against anything"
		}
		checks[6] = noDoc7(CheckCurrent("", so))
		rep.note(statementNote)
		return rep
	}
	packetChecks(&checks, doc, so)
	checks[6] = CheckCurrent(doc.ID, so)
	rep.note(statementNote)
	return rep
}

func noDoc7(c Check) Check {
	if c.Status == Pass {
		c.Status, c.Detail = NotChecked, "the statement was not verified, so what the current state is about is not established"
	}
	return c
}

const statementNote = "What exit 0 proves: the statement was signed by the issuer's key you hold, its counts are the ones the packet's records give " +
	"and those records are under a witnessed checkpoint, a witness the issuer does not run has countersigned it, and the issuer says it is current " +
	"as of the time printed. What it does not prove: that the underlying changes were good (the statement counts clearances; it does not " +
	"judge them), that the scope the subscriber chose is the whole organisation, or anything about a period the observation feeds could not see " +
	"(it is printed, not filled in). A statement never scores or ranks a subscriber."

func srcOf(have bool, from string) string {
	if have {
		return "supplied by you (" + from + ")"
	}
	return "none"
}

// c1c2 runs checks 1 and 2 and returns the document only when the signature verified.
func c1c2(checks *[7]Check, envelope []byte, so StatementOptions) *statement.Document {
	c1, c2 := &checks[0], &checks[1]
	if len(so.Keys) == 0 {
		c1.Status, c1.Detail = NotChecked, "no issuer keys were supplied: a statement cannot vouch for the key that signed it"
		c2.Status, c2.Detail = NotChecked, "no issuer keys were supplied, so the signature cannot be checked"
		return nil
	}
	payload, kid, err := token.VerifyDSSE(envelope, statement.PayloadType, so.Keys)
	switch {
	case errors.Is(err, token.ErrUnknownKey):
		c1.Status, c1.Detail = Fail, "the statement is signed by a key that is not one of the keys you supplied for the issuer"
		c2.Status, c2.Detail = NotChecked, "no key you hold signed it"
		return nil
	case errors.Is(err, token.ErrSignature):
		c1.Status, c1.Detail = Pass, "the statement names a key you hold"
		c2.Status, c2.Detail = Fail, "THE SIGNATURE DOES NOT VERIFY: the statement was altered after it was signed, or signed by another key under this key's id"
		return nil
	case err != nil:
		c1.Status, c1.Detail = NotChecked, "the file is not a statement envelope"
		c2.Status, c2.Detail = Fail, "the file is not a "+statement.PayloadType+" DSSE envelope: "+err.Error()
		return nil
	}
	doc, err := statement.Parse(payload)
	if err != nil {
		c1.Status, c1.Detail = Pass, "the statement was signed by a key you hold"
		c2.Status, c2.Detail = Fail, "the signed payload is not a statement: "+err.Error()
		return nil
	}
	if canonical, err := doc.Canonical(); err != nil || string(canonical) != string(payload) {
		c1.Status, c1.Detail = Pass, "the statement was signed by a key you hold"
		c2.Status, c2.Detail = Fail, "the signed bytes are not the canonical form of the document they carry: what is read is not what was signed"
		return nil
	}
	c2.Status, c2.Detail = Pass, fmt.Sprintf("%s of statement %s verifies under key %s", statement.Schema, doc.ID, kid[:min(8, len(kid))])
	c2.Trust = "keys you supplied"
	c1.Trust = "keys you supplied"
	switch {
	case so.Issuer == "":
		c1.Status = SelfVouched
		c1.Detail = "signed by a key you hold; the issuer's name is the statement's own claim (supply the issuer name the keys belong to)"
	case so.Issuer != doc.Issuer:
		c1.Status, c1.Detail = Fail, "the statement names a different issuer than the one your keys are for"
		return nil
	default:
		c1.Status, c1.Detail = Pass, "signed by a key you hold for the issuer you named"
	}
	return doc
}

// packetChecks runs checks 3 to 6 against the packet.
func packetChecks(checks *[7]Check, doc *statement.Document, so StatementOptions) {
	if so.PacketDir == "" && so.PacketFiles == nil {
		for i := 2; i < 6; i++ {
			checks[i].Status, checks[i].Detail = NotChecked, "no packet was supplied (the recipient detail the statement was cut from): there is nothing to check its counts against"
		}
		return
	}
	scratch := &Report{Packet: so.PacketDir}
	c := &ctx{dir: so.PacketDir, opts: so.Options, rep: scratch}
	if so.PacketFiles != nil {
		c.mem = so.PacketFiles
	}
	if c.opts.Now == nil {
		c.opts.Now = so.Now
	}
	c.manifestCheck()
	c.loadPacket()
	c.recordsCheck()
	c.ledgerCheck()
	c.figuresCheck()
	c.statementsCheck()
	c.acceptancesCheck()

	by := func(match func(string) bool) []Check {
		var out []Check
		for _, ch := range scratch.Checks {
			if match(ch.Name) {
				out = append(out, ch)
			}
		}
		return out
	}
	isWit := func(n string) bool { return n == "ledger: witness countersignatures" || n == "ledger: witness policy" }
	c3 := by(func(n string) bool {
		return n == "manifest" || n == "packet.json" || strings.HasPrefix(n, "records:") || (strings.HasPrefix(n, "ledger") && !isWit(n))
	})
	c4 := by(isWit)
	c5 := by(func(n string) bool {
		return strings.HasPrefix(n, "packet.json: counted") || strings.HasPrefix(n, "acceptances:")
	})
	c6 := by(func(n string) bool { return strings.HasPrefix(n, "packet.json: each scope") })

	// 3: the statement names this packet, these records and this checkpoint, and every one of them is under it.
	var bind []string
	md, mErr := c.read(fileManifest)
	if mErr != nil {
		bind = append(bind, "the packet has no MANIFEST.json")
	} else {
		sum := sha256.Sum256(md)
		if hex.EncodeToString(sum[:]) != doc.Packet.Digest || "pk-"+doc.Packet.Digest[:32] != doc.Packet.ID {
			bind = append(bind, "this is not the packet the statement names (its manifest digest differs)")
		}
	}
	c3 = append(c3, bindCheck("the statement names this packet", bind))
	if got := statement.CitedOf(seqHashes(c.recs)); got != doc.Cited {
		c3 = append(c3, bindCheck("the cited records are the packet's", []string{"the records the packet carries are not the records the statement cites"}))
	}
	switch {
	case doc.Cited.Count == 0:
		c3 = append(c3, Check{Name: "the statement cites a record", Status: NotChecked, Detail: "the statement cites no record: no proof can stand behind it"})
	case doc.Checkpoint == nil:
		c3 = append(c3, Check{Name: "the statement names a checkpoint", Status: NotCheckpointed, Detail: "the statement stands on no ledger checkpoint: its records are chained and recorded, and no witness has seen them"})
	case c.cp == nil:
		c3 = append(c3, Check{Name: "the checkpoint is verified", Status: NotChecked, Detail: "the packet's checkpoint was not verified"})
	default:
		cp := c.cp
		if doc.Checkpoint.Size != cp.size || doc.Checkpoint.Root != hex.EncodeToString(cp.root) || doc.Checkpoint.OriginSHA256 != sha256Hex([]byte(cp.origin)) {
			c3 = append(c3, bindCheck("the statement's checkpoint is the packet's", []string{"the checkpoint the statement names is not the one the packet carries"}))
		}
		if n := countAfter(c.recs, cp.size); n > 0 {
			c3 = append(c3, Check{Name: "every cited record is under the checkpoint", Status: NotCheckpointed,
				Detail: fmt.Sprintf("%d of the %d cited records come after the checkpoint: recorded and chained, not yet under a witnessed checkpoint (issue the statement for a period that ended before the newest checkpoint)", n, len(c.recs))})
		}
	}
	checks[2] = rollup(checks[2], c3)

	// 4: a witness Clearance does not run has countersigned the checkpoint.
	checks[3] = rollup(checks[3], witnessChecks(c, c4, doc, so))

	// 5: the counts recompute.
	der, err := derive(c, doc)
	if err != nil {
		c5 = append(c5, Check{Name: "the counts are derived from the packet", Status: Fail, Detail: err.Error()})
	} else {
		bad := statement.SameDerived(doc, der)
		var count, health, exc []string
		for _, b := range bad {
			switch {
			case b == "observation health":
				health = append(health, b)
			case strings.HasPrefix(b, "exceptions"):
				exc = append(exc, b)
			default:
				count = append(count, b)
			}
		}
		c5 = append(c5, bindCheck("the statement's counts are the packet's", count))
		health = append(health, exc...)
		c6 = append(c6, bindCheck("the statement's exceptions and health are the packet's", health))
		if missing := missingSeqs(der.ExceptionSeqs, c.recs); len(missing) > 0 {
			c6 = append(c6, bindCheck("every exception row cites a record the packet carries", []string{fmt.Sprintf("%d exception row(s) cite a record the packet does not carry", len(missing))}))
		}
		// Every class is present by construction (statement.Summarize lists them all) and the statement is held to it.
		if len(doc.Summary.Exceptions.ByClass) != len(statement.ExceptionClasses) || len(doc.Summary.ByCoverage) == 0 || doc.Summary.Health.Scopes == nil {
			c6 = append(c6, bindCheck("every coverage state, exception class and scope is listed", []string{"the statement leaves a state, a class or the health section out"}))
		}
	}
	checks[4] = rollup(checks[4], c5)
	checks[5] = rollup(checks[5], c6)
}

func derive(c *ctx, doc *statement.Document) (*statement.Derived, error) {
	pj, err := c.read(filePacket)
	if err != nil {
		return nil, errors.New("the packet carries no packet.json")
	}
	rj, err := c.read(fileRecords)
	if err != nil {
		return nil, errors.New("the packet carries no records")
	}
	return statement.Summarize(pj, rj, doc.Profile)
}

func seqHashes(rs []rec) []statement.SeqHash {
	out := make([]statement.SeqHash, 0, len(rs))
	for _, r := range rs {
		out = append(out, statement.SeqHash{Seq: r.seq, Hash: r.computed})
	}
	return out
}

func countAfter(rs []rec, size int64) int {
	n := 0
	for _, r := range rs {
		if r.seq >= size {
			n++
		}
	}
	return n
}

func missingSeqs(want []int64, rs []rec) []int64 {
	have := map[int64]bool{}
	for _, r := range rs {
		have[r.seq] = true
	}
	var out []int64
	for _, s := range want {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}

func bindCheck(name string, bad []string) Check {
	if len(bad) > 0 {
		return Check{Name: name, Status: Fail, Detail: strings.Join(bad, "; "), Findings: bad}
	}
	return Check{Name: name, Status: Pass}
}

// witnessChecks is check 4's parts: the packet verifier's witness check, and whether a countersignature is from a witness
// the issuer does not run.
func witnessChecks(c *ctx, base []Check, doc *statement.Document, so StatementOptions) []Check {
	out := slices.Clone(base)
	var wit *Check
	for i := range out {
		if out[i].Name == "ledger: witness countersignatures" {
			wit = &out[i]
		}
	}
	nocp := false
	for _, ch := range c.rep.Checks {
		if ch.Name == "ledger checkpoint and witnesses" && ch.Status == NotCheckpointed {
			out = append(out, ch)
			nocp = true
		}
	}
	if nocp || wit == nil || wit.Status != Pass || c.cp == nil {
		if !nocp && wit == nil {
			out = append(out, Check{Name: "the checkpoint is countersigned", Status: NotChecked, Detail: "the witness check did not run"})
		}
		return out
	}
	trusted, declared := so.IndependentWitnesses, false
	if len(trusted) == 0 {
		trusted, declared = doc.Witness.Independent, true
	}
	independent := 0
	for _, n := range c.cp.cosigned {
		if slices.Contains(trusted, n) {
			independent++
		}
	}
	switch {
	case independent == 0:
		out = append(out, Check{Name: "a witness the issuer does not run", Status: NotWitnessed,
			Detail: "NOT YET INDEPENDENTLY WITNESSED: no countersignature on the checkpoint is from a witness known not to be run by the issuer. The log is protected from a rewrite only by witnesses the issuer runs, or by ones whose independence is not established; an independent witness has not yet seen it"})
	case declared:
		out = append(out, Check{Name: "a witness the issuer does not run", Status: SelfVouched,
			Detail: "a countersignature is from a witness the issuer declares independent of it; supply the independent witnesses you know (--independent-witness) to check that yourself"})
	default:
		out = append(out, Check{Name: "a witness the issuer does not run", Status: Pass, Detail: fmt.Sprintf("%d countersignature(s) from a witness you know the issuer does not run", independent)})
	}
	return out
}

// rollup folds sub-checks into one: FAIL if any failed, else the weakest of the rest, else PASS. Its Detail counts and never
// quotes (a public page prints it); the sub-checks' own words are its Findings.
func rollup(top Check, subs []Check) Check {
	if len(subs) == 0 {
		top.Status, top.Detail = NotChecked, "the check did not run"
		return top
	}
	rank := map[Status]int{Fail: 6, NotChecked: 5, NotCheckpointed: 4, NotWitnessed: 3, SelfVouched: 2, Pass: 0}
	worst := Pass
	var trust []string
	for _, s := range subs {
		if rank[s.Status] > rank[worst] {
			worst = s.Status
		}
		if s.Trust != "" && !slices.Contains(trust, s.Trust) {
			trust = append(trust, s.Trust)
		}
		line := s.Name + ": " + string(s.Status)
		if s.Detail != "" && s.Status != Pass {
			line += " (" + s.Detail + ")"
		}
		top.Findings = append(top.Findings, line)
		for _, f := range s.Findings {
			top.Findings = append(top.Findings, "    "+f)
		}
	}
	top.Status = worst
	top.Trust = strings.Join(trust, "; ")
	passed := 0
	for _, s := range subs {
		if s.Status == Pass {
			passed++
		}
	}
	switch worst {
	case Pass:
		top.Detail = fmt.Sprintf("%d of %d parts passed", passed, len(subs))
	default:
		var first string
		for _, s := range subs {
			if s.Status == worst {
				first = s.Detail
				break
			}
		}
		top.Detail = first
		if worst == Fail && len(top.Detail) > 300 {
			top.Detail = fmt.Sprintf("%d of %d parts failed", len(subs)-passed, len(subs))
		}
	}
	return top
}

// CheckCurrent is check 7 against the core's own live state or a signed status. id is the statement's id ("" when the
// statement itself was not verified).
func CheckCurrent(id string, so StatementOptions) Check {
	c := Check{Name: StatementChecks[6]}
	if so.Now == nil {
		so.Now = time.Now
	}
	st := statement.Status{}
	var asOf time.Time
	switch {
	case so.Live != nil:
		st = statement.Status{State: so.Live.State, SupersededBy: so.Live.SupersededBy, RevokedAt: so.Live.RevokedAt}
		asOf = so.Live.AsOf
		c.Trust = "the issuing core's own current state"
	case len(so.Status) > 0:
		if len(so.Keys) == 0 {
			c.Status, c.Detail = NotChecked, "a status was supplied and no issuer keys: it cannot be trusted"
			return c
		}
		payload, _, err := token.VerifyDSSE(so.Status, statement.StatusPayloadType, so.Keys)
		if err != nil {
			c.Status, c.Detail = Fail, "the status does not verify under the issuer's keys: "+err.Error()
			return c
		}
		p, err := statement.ParseStatus(payload)
		if err != nil {
			c.Status, c.Detail = Fail, "the signed status is not a status: "+err.Error()
			return c
		}
		if id != "" && p.ID != id {
			c.Status, c.Detail = Fail, "the status is for another statement"
			return c
		}
		t, err := time.Parse(time.RFC3339, p.AsOf)
		if err != nil {
			c.Status, c.Detail = Fail, "the status's as_of is not an RFC 3339 time"
			return c
		}
		st, asOf = *p, t
		c.Trust = "a status signed by keys you supplied"
		max := so.StatusMaxAge
		if max <= 0 {
			max = DefaultStatusMaxAge
		}
		now := so.Now()
		switch {
		case asOf.After(now.Add(5 * time.Minute)):
			c.Status, c.Detail = Fail, "the status is dated in the future"
			return c
		case now.Sub(asOf) > max:
			c.Status = NotChecked
			c.Detail = fmt.Sprintf("the status is as of %s, older than %s: fetch a fresh one (revocation is the core's current state)", asOf.UTC().Format(time.RFC3339), max)
			return c
		}
	default:
		c.Status, c.Detail = NotChecked, "no current state was supplied: whether the statement has been superseded or revoked is the core's current state, and it is not in the statement. Fetch /s/<id>/status.json and pass it with --status"
		return c
	}
	when := asOf.UTC().Format(time.RFC3339)
	switch st.State {
	case statement.StateValid:
		c.Status, c.Detail = Pass, "not superseded and not revoked, as of "+when
	case statement.StateRevoked:
		c.Status, c.Detail = Fail, "REVOKED, as of "+when+": the issuer withdrew this statement; do not rely on it"
	case statement.StateSuperseded:
		c.Status, c.Detail = Fail, "SUPERSEDED by "+st.SupersededBy+", as of "+when+": a correction replaced it; read that one"
	default:
		c.Status, c.Detail = Fail, "the state is not one this verifier knows"
	}
	return c
}
