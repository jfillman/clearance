package pyyaml

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/jfillman/clearance/internal/pycompat"
)

// TestAgainstPyYAML: yaml.safe_load's value (as repr) or failure class, from tools/golden/gen_vectors.py.
func TestAgainstPyYAML(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases [][2]json.RawMessage
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		var doc string
		var want struct{ Repr, Error string }
		_ = json.Unmarshal(c[0], &doc)
		_ = json.Unmarshal(c[1], &want)
		v, err := SafeLoad(doc)
		var ye *Error
		var ve *ValueError
		switch {
		case want.Error == "YAMLError":
			if !errors.As(err, &ye) {
				t.Errorf("SafeLoad(%q): want a YAMLError, got %v, %v", doc, pycompat.Repr(v), err)
			}
		case want.Error != "":
			if !errors.As(err, &ve) {
				t.Errorf("SafeLoad(%q): want %s, got %v, %v", doc, want.Error, pycompat.Repr(v), err)
			}
		case err != nil:
			t.Errorf("SafeLoad(%q): %v, want %s", doc, err, want.Repr)
		default:
			if got := pycompat.Repr(v); got != want.Repr {
				t.Errorf("SafeLoad(%q) = %s, PyYAML %s", doc, got, want.Repr)
			}
		}
	}
}

func TestAliasBomb(t *testing.T) {
	doc := "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
	prev := "a"
	for i := range 12 {
		name := string(rune('b' + i))
		doc += name + ": &" + name + " [*" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + "]\n"
		prev = name
	}
	var ve *ValueError
	if _, err := SafeLoad(doc); !errors.As(err, &ve) {
		t.Fatalf("an alias bomb must fail closed (a ValueError), got %v", err)
	}
}
