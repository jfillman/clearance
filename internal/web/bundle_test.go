package web

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

// The committed placeholder says this; the real bundle never does.
const placeholderMarker = "is not built into this binary"

// TestReleaseBundleIsTheUI runs in a release-style build, where `make web-ui` (tools/webui) has replaced the
// placeholder with the pinned clearance-ui bundle (CLEARANCE_REQUIRE_UI_BUNDLE=1: the CI job and the Dockerfile's
// build stage). A plain `go test` leaves the placeholder in and skips.
func TestReleaseBundleIsTheUI(t *testing.T) {
	if os.Getenv("CLEARANCE_REQUIRE_UI_BUNDLE") != "1" {
		t.Skip("CLEARANCE_REQUIRE_UI_BUNDLE is not set: the placeholder bundle is expected")
	}
	b, err := bundle()
	if err != nil {
		t.Fatal(err)
	}
	idx, err := fs.ReadFile(b, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(idx), placeholderMarker) {
		t.Fatal("the embedded index.html is the placeholder: run `make web-ui` before building")
	}
	if !strings.Contains(string(idx), "assets/") {
		t.Error("the embedded index.html does not reference assets/: not the UI's entry page")
	}
	n := 0
	_ = fs.WalkDir(b, "assets", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if n == 0 {
		t.Error("the embedded bundle has no files under assets/")
	}
}
