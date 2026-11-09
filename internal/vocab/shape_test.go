package vocab_test

import (
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

// Shapes recorded on hangar-dev: a tier 3 proposer and a tier 2 proposer.
func TestRecordedProposerShapes(t *testing.T) {
	d := vocab.Default()
	for name, want := range map[string]bool{"user:cicd-pac[bot]": true, "user:jfillman": false} {
		bare := name[len("user:"):]
		if got := vocab.WildMatchAny(d.AutomationSubjects, name) || vocab.WildMatchAny(d.AutomationSubjects, bare); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
