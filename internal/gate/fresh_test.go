package gate_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
)

func TestParseCallMeta(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out[http.CanonicalHeaderKey(kv[i])] = []string{kv[i+1]} // set raw: Header.Set would not stop a control byte here
		}
		return out
	}
	if m, err := gate.ParseCallMeta(h()); err != nil || m.Via != "" || m.AuthTime != nil {
		t.Fatal(m, err)
	}
	for _, via := range gate.Vias {
		if m, err := gate.ParseCallMeta(h(gate.HeaderVia, via, gate.HeaderSurfaceRef, "https://x/y?z=1")); err != nil || m.Via != via {
			t.Fatal(via, m, err)
		}
	}
	if m, err := gate.ParseCallMeta(h(gate.HeaderVia, "portal"), "portal"); err != nil || m.Via != "portal" {
		t.Fatal(m, err)
	}
	for name, hdr := range map[string]http.Header{
		"unknown via":       h(gate.HeaderVia, "fax"),
		"extra not named":   h(gate.HeaderVia, "portal"),
		"ref without via":   h(gate.HeaderSurfaceRef, "x"),
		"control byte":      h(gate.HeaderVia, "cli", gate.HeaderSurfaceRef, "a\x01b"),
		"newline":           h(gate.HeaderVia, "cli", gate.HeaderSurfaceRef, "a\nb"),
		"DEL":               h(gate.HeaderVia, "cli", gate.HeaderSurfaceRef, "a\x7fb"),
		"invalid utf-8":     h(gate.HeaderVia, "cli", gate.HeaderSurfaceRef, "a\xffb"),
		"too long":          h(gate.HeaderVia, "cli", gate.HeaderSurfaceRef, strings.Repeat("a", gate.MaxSurfaceRef+1)),
		"auth time text":    h(gate.HeaderAuthTime, "now"),
		"auth time zero":    h(gate.HeaderAuthTime, "0"),
		"auth time decimal": h(gate.HeaderAuthTime, "1.5"),
	} {
		if _, err := gate.ParseCallMeta(hdr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := gate.ParseCallMeta(h(gate.HeaderVia, "cli", gate.HeaderSurfaceRef, strings.Repeat("é", gate.MaxSurfaceRef/2))); err != nil {
		t.Errorf("512 bytes of text refused: %v", err)
	}
}
