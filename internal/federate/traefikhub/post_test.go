package traefikhub_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/federate/traefikhub"
)

func TestARerunPostsNothingTwice(t *testing.T) {
	f := newCore(t)
	path := filepath.Join(t.TempDir(), "state")
	run := func() traefikhub.PostStats {
		recs, _, err := traefikhub.Ingest(open(t, "lab-hub.log"), open(t, "lab-access.log"), traefikhub.Options{})
		if err != nil {
			t.Fatal(err)
		}
		st, closer, err := traefikhub.OpenState(path)
		if err != nil {
			t.Fatal(err)
		}
		defer closer.Close()
		ps, err := traefikhub.PostCounted(context.Background(), f.client, recs, st)
		if err != nil {
			t.Fatal(err)
		}
		return ps
	}
	if ps := run(); ps.Posted != 4 || ps.Skipped != 0 {
		t.Fatal(ps)
	}
	if ps := run(); ps.Posted != 0 || ps.Skipped != 4 {
		t.Fatal(ps)
	}
	if n := len(f.records(t)); n != 4 {
		t.Fatalf("%d records", n)
	}
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := traefikhub.OpenState(path); err == nil || !strings.Contains(err.Error(), "not a key") {
		t.Fatal(err)
	}
}
