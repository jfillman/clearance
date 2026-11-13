package slack

import (
	"os"
	"testing"
	"time"
)

func storeConformance(t *testing.T, st Store) {
	t.Helper()
	if err := st.Migrate(bg); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	l := Link{Team: "T1", User: "U1", Issuer: "https://idp", Subject: "s1", Person: "user:ann", AuthTime: 1700000000, LinkedAt: now, VerifiedAt: now, DM: true}
	if got, err := st.GetLink(bg, "T1", "U1"); err != nil || got != nil {
		t.Fatalf("no link yet: %v %v", got, err)
	}
	if err := st.PutLink(bg, l); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetLink(bg, "T1", "U1")
	if got == nil || got.Person != "user:ann" || got.AuthTime != 1700000000 || !got.VerifiedAt.Equal(now) || !got.DM {
		t.Fatalf("round trip: %+v", got)
	}
	if other, _ := st.GetLink(bg, "T2", "U1"); other != nil {
		t.Fatal("a link is per workspace")
	}
	if err := st.SetDM(bg, "T1", "U1", false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDM(bg, "T9", "U9", false); err != ErrNotFound {
		t.Errorf("SetDM on no link: %v", err)
	}
	l.User, l.Person = "U2", "user:bob"
	st.PutLink(bg, l)
	all, _ := st.ListLinks(bg)
	if len(all) != 2 || all[0].DM {
		t.Fatalf("list: %+v", all)
	}
	if ok, _ := st.DeleteLink(bg, "T1", "U1"); !ok {
		t.Error("delete")
	}
	if ok, _ := st.DeleteLink(bg, "T1", "U1"); ok {
		t.Error("delete twice")
	}

	m := Message{ChangeID: "c-1", Dest: "channel:C1", Channel: "C1", TS: "1.1", Rendered: "d", StateKey: "holding|0", Ref: "web|prod", Open: true}
	st.PutMessage(bg, m)
	m2 := m
	m2.Dest, m2.Channel = "dm:T1:U2", "D2"
	st.PutMessage(bg, m2)
	m.Link, m.Open = "https://x/p1", false
	st.PutMessage(bg, m) // an upsert
	ms, _ := st.Messages(bg, "c-1")
	if len(ms) != 2 || ms[0].Link != "https://x/p1" || ms[0].Open || ms[0].Ref != "web|prod" || ms[0].StateKey != "holding|0" {
		t.Fatalf("messages: %+v", ms)
	}
	if open, _ := st.OpenMessages(bg); len(open) != 1 || open[0].Dest != "dm:T1:U2" {
		t.Fatalf("open: %+v", open)
	}
	if _, ok, _ := st.KV(bg, "k"); ok {
		t.Error("no key yet")
	}
	st.SetKV(bg, "k", "1")
	st.SetKV(bg, "k", "2")
	if v, ok, _ := st.KV(bg, "k"); !ok || v != "2" {
		t.Errorf("kv: %q", v)
	}
}

func TestMemStore(t *testing.T) { storeConformance(t, NewMemStore()) }

// TestPGStore runs the same checks on a scratch Postgres (CLEARANCE_TEST_DSN; skipped without it).
func TestPGStore(t *testing.T) {
	dsn := os.Getenv("CLEARANCE_TEST_DSN")
	if dsn == "" {
		t.Skip("CLEARANCE_TEST_DSN is not set")
	}
	pg, err := OpenPG(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if err := pg.Migrate(bg); err != nil {
		t.Fatal(err)
	}
	if err := pg.Migrate(bg); err != nil { // migrating twice is a no-op
		t.Fatal(err)
	}
	pg.Pool.Exec(bg, `TRUNCATE clearance_slack_links, clearance_slack_messages, clearance_slack_kv`)
	storeConformance(t, pg)
	pg.Pool.Exec(bg, `TRUNCATE clearance_slack_links, clearance_slack_messages, clearance_slack_kv`)
}
