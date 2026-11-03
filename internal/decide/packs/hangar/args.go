package hangar

import (
	"math/big"
	"path"
	"regexp"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/scope"
)

// full is Python's re.fullmatch: the whole string. match is re.match on a pattern ending in `$`, which also
// accepts one trailing newline.
func full(p string) *regexp.Regexp  { return regexp.MustCompile(`\A(?:` + p + `)\z`) }
func match(p string) *regexp.Regexp { return regexp.MustCompile(`\A(?:` + p + `)\n?\z`) }

// glidepath-api's own path rules (args.py _GP_ARGS), in the Python's order.
var gpArgs = []struct {
	key string
	re  *regexp.Regexp
}{
	{"app", full(`[a-z0-9][a-z0-9-]{0,62}`)},
	{"result", full(`[0-9a-f-]{36}`)},
	{"taskRun", full(`[a-z0-9][a-z0-9.-]{0,252}`)},
	{"pipelinerun", full(`[a-z0-9][a-z0-9.-]{0,252}`)},
	{"chainId", full(`[A-Za-z0-9][A-Za-z0-9._-]{0,252}`)},
	{"env", full(`[A-Za-z0-9][A-Za-z0-9._-]{0,62}`)},
	{"cluster", full(`[A-Za-z0-9][A-Za-z0-9._-]{0,62}`)},
	{"sourceEnv", full(`[A-Za-z0-9][A-Za-z0-9._-]{0,62}`)},
	{"sourceCluster", full(`[A-Za-z0-9][A-Za-z0-9._-]{0,62}`)},
	{"sourceImageRepo", full(`[a-z0-9][a-z0-9._/:-]{0,254}`)},
	{"sourceImageTag", full(`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`)},
	{"container", full(`[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`)},
	{"name", full(`(promote|rollback)-[a-z0-9-]{1,56}`)},
	{"image", full(`ghcr\.io/[a-z0-9._/-]{1,255}(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(@sha256:[0-9a-f]{64})?`)},
	{"id", full(`[A-Za-z0-9_-]{1,128}`)},
	{"type", full(`[a-z0-9.]{1,256}`)},
	{"since", full(`[0-9A-Za-z:.+_-]{1,64}`)},
	{"targetReleaseId", full(`[\x21-\x7e]{1,256}`)},
}

var gpRef = full(`[A-Za-z0-9][A-Za-z0-9._/-]{0,255}`)

const gpPatchBytes = 256 << 10

func strOf(m *pycompat.Map, k string) (string, bool, bool) {
	v, present := m.GetStr(k)
	s, isStr := v.(string)
	return s, isStr, present
}

// intIn is `isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi`.
func intIn(v any, lo, hi int64) bool {
	switch x := v.(type) {
	case int64:
		return lo <= x && x <= hi
	case *big.Int:
		return false // outside int64, so outside any bound here
	}
	return false
}

func glidepathBadArgs(a *pycompat.Map) int {
	bad := 0
	for _, g := range gpArgs {
		if s, isStr, present := strOf(a, g.key); present && !(isStr && g.re.MatchString(s)) {
			bad++
		}
	}
	for _, b := range []struct {
		k  string
		hi int64
	}{{"sinceHours", 744}, {"limit", 1000}, {"timeoutSeconds", 120}} {
		if v, ok := a.GetStr(b.k); ok && !intIn(v, 1, b.hi) {
			bad++
		}
	}
	if v, ok := a.GetStr("dryRun"); ok {
		if _, isBool := v.(bool); !isBool {
			bad++
		}
	}
	if s, isStr, present := strOf(a, "reason"); present && !(isStr && between(pycompat.Len(pycompat.Strip(s)), 1, 1024)) {
		bad++
	}
	if v, ok := a.GetStr("patch"); ok {
		m, isMap := v.(*pycompat.Map)
		n := 0
		if isMap {
			n, _ = pycompat.DumpsLen(m)
		}
		if !isMap || n > gpPatchBytes {
			bad++
		}
	}
	if s, isStr, present := strOf(a, "title"); present && !(isStr && between(pycompat.Len(pycompat.Strip(s)), 1, 200)) {
		bad++
	}
	if s, isStr, present := strOf(a, "body"); present && !(isStr && pycompat.Len(s) <= 4000) {
		bad++
	}
	for _, k := range []string{"baseRef", "branch"} {
		if s, isStr, present := strOf(a, k); present && !(isStr && gpRef.MatchString(s) && !strings.Contains(s, "..")) {
			bad++
		}
	}
	return bad
}

func between(n, lo, hi int) bool { return lo <= n && n <= hi }

// glidepathPromoteSourceOK: a promotion names exactly one whole source pair.
func glidepathPromoteSourceOK(a *pycompat.Map) bool {
	given := map[string]bool{}
	for _, k := range []string{"sourceEnv", "sourceCluster", "sourceImageRepo", "sourceImageTag"} {
		if v, ok := a.GetStr(k); ok && !(v == nil || v == "") {
			given[k] = true
		}
	}
	if len(given) != 2 {
		return false
	}
	return (given["sourceEnv"] && given["sourceCluster"]) || (given["sourceImageRepo"] && given["sourceImageTag"])
}

var afArgs = []struct {
	key string
	re  *regexp.Regexp
}{
	{"app", match(`[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`)},
	{"env", match(`[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`)},
	{"name", match(`[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?`)},
	{"kind", match(`[A-Za-z][A-Za-z0-9]{0,62}`)},
	{"rule", match(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`)},
}

var (
	afSections = map[string]bool{"chart": true, "xrds": true, "components": true, "targets": true, "kinds": true}
	afDocName  = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.ya?ml\n?\z`)
)

const afMaxDocs, afMaxBytes = 20, 256 << 10

func afDocumentOK(d any) bool {
	m, ok := d.(*pycompat.Map)
	if !ok {
		return false
	}
	for _, k := range m.Keys() {
		if k != "path" && k != "content" {
			return false
		}
	}
	content, isStr, _ := strOf(m, "content")
	if !isStr {
		return false
	}
	p, _ := m.GetStr("path")
	n, err := scope.NormalizeAny(p)
	if err != nil {
		return false
	}
	return afDocName.MatchString(path.Base(n)) && len(content) <= afMaxBytes
}

func airframeBadArgs(a *pycompat.Map) int {
	bad := 0
	for _, g := range afArgs {
		if s, isStr, present := strOf(a, g.key); present && !(isStr && g.re.MatchString(s)) {
			bad++
		}
	}
	if v, ok := a.GetStr("section"); ok {
		s, isStr := v.(string)
		if !isStr || !afSections[s] {
			bad++
		}
	}
	if v, ok := a.GetStr("documents"); ok {
		docs, isList := v.([]any)
		good := isList && len(docs) >= 1 && len(docs) <= afMaxDocs
		for _, d := range docs {
			if !good {
				break
			}
			good = afDocumentOK(d)
		}
		if !good {
			bad++
		}
	}
	if v, ok := a.GetStr("mode"); ok && v != "values" && v != "xr" {
		bad++
	}
	if v, ok := a.GetStr("render"); ok {
		if _, isBool := v.(bool); !isBool {
			bad++
		}
	}
	if v, ok := a.GetStr("spec"); ok {
		if _, isMap := v.(*pycompat.Map); !isMap {
			bad++
		}
	}
	if v, ok := a.GetStr("baseCicd"); ok {
		_, isMap := v.(*pycompat.Map)
		s, isStr := v.(string)
		if !isMap && !(isStr && pycompat.Len(s) <= afMaxBytes) {
			bad++
		}
	}
	return bad
}
