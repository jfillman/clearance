package vocab

import "strings"

// DefaultAutomationSubjects are the product-neutral shapes of an approver's name or subject that mark automation:
// a bot account (GitHub's "name[bot]", "name-bot", "bot-name"), a service-account or machine principal
// ("system:serviceaccount:...", "serviceaccount:...", "svc-*", a SPIFFE id, a cloud service-account address) and an
// agent identity ("agent:*", "agent-*"). Platform names belong in CLEARANCE_AUTOMATION_SUBJECTS, not here.
func DefaultAutomationSubjects() []string {
	return []string{"*[bot]", "*-bot", "bot-*", "bot:*", "app/*", "agent:*", "agent-*", "*-agent", "system:*",
		"serviceaccount:*", "service-account:*", "svc-*", "spiffe://*", "*.iam.gserviceaccount.com"}
}

// DefaultAutomationIssuers are the issuers whose tokens are never a person's: a Kubernetes API server (a
// TokenReview or projected service-account token), GitHub Actions' OIDC, and an ID-JAG agent-identity issuer.
func DefaultAutomationIssuers() []string {
	return []string{"*kubernetes*", "*.svc", "*.svc.*", "*token.actions.githubusercontent.com*", "*id-jag*", "*idjag*"}
}

func noneIsEmpty(s string) []string {
	if strings.EqualFold(strings.TrimSpace(s), "none") {
		return []string{}
	}
	return list(s)
}

// WildMatch reports whether name matches pattern, where * stands for any run of characters (and nothing else is
// special, so "[bot]" is literal), ignoring case.
func WildMatch(pattern, name string) bool {
	p, n := strings.ToLower(pattern), strings.ToLower(name)
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return p == n
	}
	if !strings.HasPrefix(n, parts[0]) {
		return false
	}
	n = n[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(n, mid)
		if i < 0 {
			return false
		}
		n = n[i+len(mid):]
	}
	return strings.HasSuffix(n, last)
}

// WildMatchAny reports whether name matches any of patterns.
func WildMatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if WildMatch(p, name) {
			return true
		}
	}
	return false
}
