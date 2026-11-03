package provenance_test

import (
	"os"
	"testing"

	"github.com/jfillman/clearance/internal/vocab/vocabtest"
)

// The tests are written against the lab deployment's vocabulary (vocabtest.Lab).
func TestMain(m *testing.M) { os.Exit(vocabtest.Main(m)) }
