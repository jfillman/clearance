package vocab_test

import (
	"reflect"
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

func TestTheAICoauthorMatchers(t *testing.T) {
	email := []vocab.Coauthor{{Email: "noreply@anthropic.com"}}
	named, err := vocab.ParseCoauthors("  Claude   Code <NoReply@Anthropic.com> ")
	if err != nil || !reflect.DeepEqual(named, []vocab.Coauthor{{Name: "claude code", Email: "noreply@anthropic.com"}}) {
		t.Fatal(named, err)
	}
	for _, tc := range []struct {
		cs   []vocab.Coauthor
		line string
		want bool
	}{
		{email, "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", true},
		{email, "co-authored-by: claude <NOREPLY@ANTHROPIC.COM>", true},
		{email, "  Co-authored-by:   Claude   <noreply@anthropic.com>  ", true},
		{email, "Assisted-by: Claude <noreply@anthropic.com>", true},
		{email, "GENERATED-BY: Claude <noreply@anthropic.com>", true},
		{email, "Co-Authored-By: <noreply@anthropic.com>", true},
		{email, "Signed-off-by: Claude <noreply@anthropic.com>", false},
		{email, "Co-Authored-By: Dana <dana@example.com>", false},
		{email, "Co-Authored-By: Claude <noreply@anthropic.com.evil>", false},
		{email, "Co-Authored-By: Claude <evil-noreply@anthropic.com>", false},
		{email, "Co-Authored-By: Claude noreply@anthropic.com", false},
		{email, "noreply@anthropic.com", false},
		{email, "", false},
		{nil, "Co-Authored-By: Claude <noreply@anthropic.com>", false},
		{named, "Co-Authored-By: CLAUDE  code <noreply@anthropic.com>", true},
		{named, "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", false},
		{named, "Co-Authored-By: <noreply@anthropic.com>", false},
	} {
		if got := vocab.MatchTrailer(tc.cs, tc.line); got != tc.want {
			t.Errorf("%v %q: %v, want %v", tc.cs, tc.line, got, tc.want)
		}
	}
}

func TestTheDefaultMatchersKnowTheWellKnownAgents(t *testing.T) {
	d := vocab.Default().AICoauthors
	for _, line := range []string{
		"Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
		"Co-authored-by: Codex <noreply@openai.com>",
		"Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>",
		"Co-authored-by: Cursor <cursoragent@cursor.com>",
		"Co-authored-by: aider (anthropic/claude-sonnet-4) <aider@aider.chat>",
	} {
		if !vocab.MatchTrailer(d, line) {
			t.Errorf("the default does not match %q", line)
		}
	}
	if vocab.MatchTrailer(d, "Co-authored-by: Dana <dana@example.com>") {
		t.Fatal("a person matched")
	}
}

func TestCLEARANCE_AI_COAUTHORS(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	v, err := vocab.FromEnv(env(nil))
	if err != nil || !reflect.DeepEqual(v.AICoauthors, vocab.DefaultAICoauthors()) {
		t.Fatal("unset is the default", v.AICoauthors, err)
	}
	v, err = vocab.FromEnv(env(map[string]string{"CLEARANCE_AI_COAUTHORS": "none"}))
	if err != nil || len(v.AICoauthors) != 0 || vocab.MatchTrailer(v.AICoauthors, "Co-Authored-By: Claude <noreply@anthropic.com>") {
		t.Fatal("none turns it off", v.AICoauthors, err)
	}
	v, err = vocab.FromEnv(env(map[string]string{"CLEARANCE_AI_COAUTHORS": "<bot@acme.dev>, Acme Agent <agent@acme.dev>,,"}))
	if err != nil || !reflect.DeepEqual(v.AICoauthors, []vocab.Coauthor{{Email: "bot@acme.dev"}, {Name: "acme agent", Email: "agent@acme.dev"}}) {
		t.Fatal(v.AICoauthors, err)
	}
	for _, bad := range []string{"Claude", "Claude <>", "<not an email>", "a <b@c> d"} {
		if _, err := vocab.FromEnv(env(map[string]string{"CLEARANCE_AI_COAUTHORS": bad})); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
