package targets

import (
	"strings"
	"testing"
)

func good(id string) Target {
	return Target{ID: id, Name: id, Kind: "k8s-namespace", Group: "hangar-prod", Env: "prod", App: "gate-api", Registry: "flight",
		Scope: "hangar-prod", Gates: []Gate{{Type: "glidepath", Instance: "gate-api-cicd", Mode: "enforce"}},
		Observers: []Observer{{Provider: "observe-k8s", Source: "observe-k8s"}}}
}

func TestNormalizeSortsAndDigestsTheContent(t *testing.T) {
	a, err := Normalize([]Target{good("b"), good("a")})
	if err != nil || a[0].ID != "a" || a[1].ID != "b" {
		t.Fatalf("%v %v", a, err)
	}
	b, _ := Normalize([]Target{good("a"), good("b")})
	if Digest(a) != Digest(b) || len(Digest(a)) != 64 {
		t.Fatal("the digest depends on the order the publisher listed them")
	}
	c := good("a")
	c.Gates[0].Mode = "flag"
	d, _ := Normalize([]Target{c, good("b")})
	if Digest(d) == Digest(a) {
		t.Fatal("a mode change did not change the digest")
	}
	if _, err := Normalize(nil); err == nil {
		t.Fatal("nil is not a set")
	}
	if e, err := Normalize([]Target{}); err != nil || len(e) != 0 {
		t.Fatalf("an empty set withdraws: %v %v", e, err)
	}
}

func TestValidateIsStrict(t *testing.T) {
	long := strings.Repeat("x", MaxText+1)
	for name, edit := range map[string]func(*Target){
		"id upper":    func(x *Target) { x.ID = "Gate" },
		"id empty":    func(x *Target) { x.ID = "" },
		"kind":        func(x *Target) { x.Kind = "vm" },
		"registry":    func(x *Target) { x.Registry = "Not A Tier" },
		"scope space": func(x *Target) { x.Scope = "a b" },
		"scope long":  func(x *Target) { x.Scope = long },
		"name long":   func(x *Target) { x.Name = long },
		"name ctl":    func(x *Target) { x.Name = "a\nb" },
		"group empty": func(x *Target) { x.Group = "" },
		"gates nil":   func(x *Target) { x.Gates = nil },
		"obs nil":     func(x *Target) { x.Observers = nil },
		"mode":        func(x *Target) { x.Gates[0].Mode = "warn" },
		"type":        func(x *Target) { x.Gates[0].Type = "G T" },
		"instance":    func(x *Target) { x.Gates[0].Instance = "" },
		"dup gate":    func(x *Target) { x.Gates = append(x.Gates, x.Gates[0]) },
		"provider":    func(x *Target) { x.Observers[0].Provider = "P" },
		"source":      func(x *Target) { x.Observers[0].Source = "" },
		"dup obs":     func(x *Target) { x.Observers = append(x.Observers, x.Observers[0]) },
		"too many gates": func(x *Target) {
			x.Gates = nil
			for i := 0; i <= MaxGates; i++ {
				x.Gates = append(x.Gates, Gate{Type: "t", Instance: string(rune('a'+i%26)) + strings.Repeat("i", i), Mode: "flag"})
			}
		},
	} {
		x := good("a")
		edit(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	x := good("a")
	if err := x.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Normalize([]Target{good("a"), good("a")}); err == nil {
		t.Fatal("a duplicate id")
	}
	many := make([]Target, MaxTargets+1)
	for i := range many {
		many[i] = good("t")
	}
	if _, err := Normalize(many); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("the cap: %v", err)
	}
}
