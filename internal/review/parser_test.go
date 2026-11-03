package review_test

import (
	"fmt"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"os"
	"testing"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/profile"
)

// parseDef is the definition parser these tests use: deftest's stand-in, then (TestMain runs the package twice)
// the real one, profile.Parser, so the ported tests hold for the parser production wires in.
var parseDef definitions.Parser = deftest.Parse

func TestMain(m *testing.M) {
	vocabtest.UseMainVocabulary()
	code := m.Run()
	if code == 0 {
		fmt.Println("again with profile.Parser")
		parseDef = profile.Parser()
		code = m.Run()
	}
	os.Exit(code)
}
