package gate

import (
	"fmt"
	"testing"
)

// Every role of a change's own set is bounded, proposers and promoters too (a change with no tree record keeps its set
// itself), and a refused absorb leaves the change as it was.
func TestAbsorbBoundsEveryRoleAndIsAtomic(t *testing.T) {
	names := func(n int) []string {
		var xs []string
		for i := 0; i < n; i++ {
			xs = append(xs, fmt.Sprintf("u%d", i))
		}
		return xs
	}
	for role, p := range map[string]people{
		"proposers": {proposers: names(MaxTreePeople + 2)},
		"promoters": {promoters: names(MaxTreePeople + 2)},
		"authors":   {authors: names(MaxTreePeople + 2)},
		"mergers":   {mergers: names(MaxTreePeople + 2)},
	} {
		c := &Change{Proposer: "first"}
		if _, err := c.absorb(p); err == nil {
			t.Errorf("%s: no refusal past the bound", role)
		}
		if len(c.AlsoBehind) != 0 || c.Source != nil {
			t.Errorf("%s: a refused absorb changed the change: %+v %+v", role, c.AlsoBehind, c.Source)
		}
	}
	c := &Change{Proposer: "first"}
	if _, err := c.absorb(people{proposers: names(MaxTreePeople - 1)}); err != nil {
		t.Fatal(err) // first + 255 others = 256
	}
}
