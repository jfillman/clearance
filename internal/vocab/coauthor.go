package vocab

import (
	"fmt"
	"strings"
)

// Coauthor matches one AI coding agent's commit trailer: Email always, Name too when it is set. Both are kept
// lower-cased with whitespace collapsed, the form Match compares.
type Coauthor struct {
	Name  string
	Email string
}

// CoauthorKeys are the trailer keys a Coauthor is matched on (lower-cased).
var CoauthorKeys = []string{"co-authored-by", "assisted-by", "generated-by"}

// DefaultAICoauthors are the trailers well-known AI coding agents add to the commits they make for a person, by
// email alone (the name carries the model, which changes). Sources, checked 2026-11-03 (docs/provenance-app.md,
// AI co-author trailers):
//
//	noreply@anthropic.com                           Claude Code: "Co-Authored-By: <model> <noreply@anthropic.com>"
//	                                                (code.claude.com/docs/en/settings-reference, attribution.commit)
//	noreply@openai.com                              OpenAI Codex: "Co-authored-by: Codex <noreply@openai.com>"
//	                                                (github.com/openai/codex pull 11617)
//	223556219+copilot@users.noreply.github.com      GitHub Copilot CLI: "Co-authored-by: Copilot <...>"
//	                                                (github.com/orgs/community/discussions/203517)
//	cursoragent@cursor.com                          Cursor's agent: "Co-authored-by: Cursor <cursoragent@cursor.com>"
//	                                                (forum.cursor.com/t/150096; github.com/block/aittributor pull 15)
//	aider@aider.chat                                aider: "Co-authored-by: aider (<model>) <aider@aider.chat>"
//	                                                (github.com/Aider-AI/aider aider/repo.py)
func DefaultAICoauthors() []Coauthor {
	return []Coauthor{{Email: "noreply@anthropic.com"}, {Email: "noreply@openai.com"},
		{Email: "223556219+copilot@users.noreply.github.com"}, {Email: "cursoragent@cursor.com"}, {Email: "aider@aider.chat"}}
}

// fold is s lower-cased with its runs of whitespace collapsed to one space and trimmed.
func fold(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// splitIdent is "Name <email>" as its name and email ("<email>" or a bare email: no name). ok is false when there
// is no email.
func splitIdent(s string) (name, email string, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "<"); i >= 0 && strings.HasSuffix(s, ">") {
		name, email = s[:i], s[i+1:len(s)-1]
	} else if !strings.ContainsAny(s, "<> \t") {
		email = s
	}
	email = strings.TrimSpace(email)
	if email == "" || strings.ContainsAny(email, "<> \t") || !strings.Contains(email, "@") {
		return "", "", false
	}
	return fold(name), strings.ToLower(email), true
}

// ParseCoauthors is CLEARANCE_AI_COAUTHORS: "none", or comma-separated "<email>", "email" or "Name <email>".
func ParseCoauthors(s string) ([]Coauthor, error) {
	out := []Coauthor{}
	if strings.TrimSpace(strings.ToLower(s)) == "none" {
		return out, nil
	}
	for _, x := range strings.Split(s, ",") {
		if strings.TrimSpace(x) == "" {
			continue
		}
		name, email, ok := splitIdent(x)
		if !ok {
			return nil, fmt.Errorf("%q is not \"<email>\" or \"Name <email>\"", strings.TrimSpace(x))
		}
		out = append(out, Coauthor{name, email})
	}
	return out, nil
}

// MatchTrailer is whether one commit-message line is a Co-Authored-By, Assisted-by or Generated-by trailer that
// one of cs matches: the key case-insensitively, the email case-insensitively, the name (when the matcher has one)
// case-insensitively with whitespace collapsed.
func MatchTrailer(cs []Coauthor, line string) bool {
	key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok || !IsCoauthorKey(key) {
		return false
	}
	name, email, ok := splitIdent(value)
	if !ok {
		return false
	}
	for _, c := range cs {
		if c.Email == email && (c.Name == "" || c.Name == name) {
			return true
		}
	}
	return false
}

// IsCoauthorKey is whether key (trimmed, any case) is one of CoauthorKeys.
func IsCoauthorKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, x := range CoauthorKeys {
		if k == x {
			return true
		}
	}
	return false
}
