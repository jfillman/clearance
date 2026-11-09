package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/vocab"
)

// sessionDigest is what an approval keeps of the approver's session: a digest of issuer and session id, or "".
func sessionDigest(iss, sid string) string {
	if sid == "" {
		return ""
	}
	h := sha256.Sum256([]byte(iss + "\x00" + sid))
	return hex.EncodeToString(h[:12])
}

// KindPerson is the kind an approval records once the route has checked it is a person (DG-APPROVER-AUTOMATION
// and DG-APPROVER-SAME, rule GATE-APPROVER-001).
const KindPerson = "person"

func bareName(s string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "user:")
}

// automationMark is why name, sub or iss marks an approver as automation, or "". Patterns are the vocabulary's
// (vocab.Vocabulary.AutomationSubjects and AutomationIssuers); each is tried on the value as written and without a
// "user:" prefix.
func automationMark(v vocab.Vocabulary, names []string, iss string) string {
	for _, n := range names {
		if n == "" {
			continue
		}
		if vocab.WildMatchAny(v.AutomationSubjects, n) || vocab.WildMatchAny(v.AutomationSubjects, bareName(n)) {
			return "the name " + n
		}
	}
	if iss != "" && vocab.WildMatchAny(v.AutomationIssuers, iss) {
		return "the issuer " + iss
	}
	return ""
}

func automationRefusal(who, why string) error {
	return gerr("DG-APPROVER-AUTOMATION", who+" is automation ("+why+"), not a person",
		"A tier 3 approval needs a person signed in at the identity provider; a service account, a bot or an agent cannot approve.", 403)
}

// checkApproverKind is the first half of GATE-APPROVER-001, run before the role is chosen: a principal that is not a
// person (a service account, GitHub Actions, a foreign workload) is refused by Clear before the person is
// resolved, and neither the person
// nor, when they signed in themselves, their subject or issuer may match the vocabulary's automation patterns. A
// delegate (Tower's backend) is a service identity by design and is not tested: the person it names is.
func checkApproverKind(onBehalfOf, person string, who identity) error {
	v := vocab.Get()
	iss := ""
	if onBehalfOf == "" && who.iss != UnattestedIssuer {
		iss = who.iss
	}
	if why := automationMark(v, []string{person, who.sub}, iss); why != "" {
		return automationRefusal(person, why)
	}
	return nil
}

// approverKeys are the names one approval is known by, resolved through the vocabulary's aliases: the person, the
// subject, the subject at its real issuer (not a delegate's) and the session. Two approvals sharing a key are one
// approver.
func approverKeys(person string, who identity, sid string, viaDelegate bool) []string {
	v := vocab.Get()
	names := []string{bareName(person)}
	if who.sub != "" {
		names = append(names, bareName(who.sub))
		if !viaDelegate && who.iss != "" {
			names = append(names, strings.ToLower(who.iss)+"|"+strings.ToLower(who.sub))
		}
	}
	var keys []string
	for _, n := range names {
		keys = append(keys, n)
		for gi, g := range v.ApproverAliases {
			for _, a := range g {
				if bareName(a) == n {
					keys = append(keys, "alias:"+strconv.Itoa(gi))
				}
			}
		}
	}
	if sid != "" && !viaDelegate {
		keys = append(keys, "session:"+sid)
	}
	return keys
}

// checkApproverDistinct is the second half of GATE-APPROVER-001: the new approval must not resolve to the same
// subject (through a name, an alias or a session) as one already on the change.
func checkApproverDistinct(c *Change, person string, who identity, sid string, viaDelegate bool) error {
	have := map[string]bool{}
	for _, k := range approverKeys(person, who, sid, viaDelegate) {
		have[k] = true
	}
	for _, a := range c.Approvals {
		ai := identity{sub: a.Sub, iss: a.Iss}
		delegated := strings.HasPrefix(a.Iss, "delegate:")
		for _, k := range approverKeys(a.Person, ai, a.Session, delegated) {
			if have[k] {
				return gerr("DG-APPROVER-SAME", person+" is the same approver as "+a.Person+" (one subject, alias or session)",
					"The two tier 3 approvers must be distinct people at the identity provider.", 409)
			}
		}
	}
	return nil
}
