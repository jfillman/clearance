package argosrc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz targets for the generic renderer's path and option handling (W-34 F7): an Application's source path, its value
// files and file parameters (resolveFileOrDirectory, resolveValueFile, sourcePath), the sources parameter (ParseSources)
// and argocd-cm's kustomize build options (checkBuildOptions). Nothing panics, and whatever is accepted stays inside the
// repository (or is an allow-listed option, unchanged). CI runs each target for 30 s (the cmp-fuzz job).

func inside(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+string(os.PathSeparator))
}

var pathSeeds = []string{
	"", ".", "..", "values.yaml", "app/values.yaml", "/values.yaml", "/app/../values.yaml", "../x", "app/../../x",
	"/../../etc/passwd", "/etc/passwd", "//etc", "inlink.yaml", "indir/values.yaml", "loop", "a\x00b", `..\..\x`,
	"https://example.test/values.yaml", "s3://b/k", "file:///etc/passwd", "$ARGOCD_APP_NAME/values.yaml", "app/",
}

// repoFixture is a checkout: app/ (the Application's path), values.yaml at the root and in app/, inlink.yaml (a link
// to values.yaml), indir (a link to app/) and loop (a link to itself). No link leaves it: a checkout with a link that
// does is refused as a whole before any of these functions runs (checkSymlinks).
func repoFixture(f *testing.F) (root, app string) {
	f.Helper()
	root = f.TempDir()
	app = filepath.Join(root, "app")
	for _, p := range []string{filepath.Join(root, "values.yaml"), filepath.Join(app, "values.yaml"), filepath.Join(app, "sub", "x.yaml")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("a: 1\n"), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	for link, target := range map[string]string{"inlink.yaml": "values.yaml", "indir": "app", "loop": "loop"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			f.Fatal(err)
		}
	}
	return root, app
}

// FuzzResolveFileOrDirectory is Argo CD's own rule for a value file or a file parameter: relative to the app path, or
// with a leading slash to the repository root, and in either case inside the repository once links are followed.
func FuzzResolveFileOrDirectory(f *testing.F) {
	root, app := repoFixture(f)
	for _, s := range pathSeeds {
		f.Add(s, false)
		f.Add(s, true)
	}
	absRoot, _ := filepath.Abs(root)
	realRoot, _ := filepath.EvalSymlinks(root)
	f.Fuzz(func(t *testing.T, p string, allowRoot bool) {
		got, err := resolveFileOrDirectory(app, root, p, allowRoot)
		if err != nil {
			return
		}
		if !inside(got, absRoot) {
			t.Fatalf("resolveFileOrDirectory(%q) = %q, outside %q", p, got, absRoot)
		}
		if got == absRoot && !allowRoot {
			t.Fatalf("resolveFileOrDirectory(%q) = the root, which is not allowed", p)
		}
		if r, err := filepath.EvalSymlinks(got); err == nil && !inside(r, realRoot) {
			t.Fatalf("resolveFileOrDirectory(%q) = %q, which resolves to %q outside the repository", p, got, r)
		}
	})
}

// FuzzResolveValueFile adds the URL rule: a value file with a scheme is refused as unsupported, never fetched.
func FuzzResolveValueFile(f *testing.F) {
	root, app := repoFixture(f)
	for _, s := range pathSeeds {
		f.Add(s)
	}
	absRoot, _ := filepath.Abs(root)
	f.Fuzz(func(t *testing.T, p string) {
		got, err := resolveValueFile(app, root, p)
		if err != nil {
			return
		}
		if !inside(got, absRoot) || got == absRoot {
			t.Fatalf("resolveValueFile(%q) = %q, outside %q or the root itself", p, got, absRoot)
		}
	})
}

// FuzzSourcePath is the Application's spec.source.path: a directory inside the repository, links resolved.
func FuzzSourcePath(f *testing.F) {
	root, _ := repoFixture(f)
	for _, s := range pathSeeds {
		f.Add(s)
	}
	realRoot, _ := filepath.EvalSymlinks(root)
	f.Fuzz(func(t *testing.T, rel string) {
		got, err := sourcePath(root, rel)
		if err != nil {
			return
		}
		if !inside(got, realRoot) {
			t.Fatalf("sourcePath(%q) = %q, outside %q", rel, got, realRoot)
		}
		if st, err := os.Stat(got); err != nil || !st.IsDir() {
			t.Fatalf("sourcePath(%q) = %q, not a directory", rel, got)
		}
	})
}

// FuzzCheckBuildOptions is argocd-cm's kustomize.buildOptions: accepted options are passed on exactly as written, and
// every one is on the allow list with an allowed value.
func FuzzCheckBuildOptions(f *testing.F) {
	for _, s := range []string{
		"", "--reorder none", "--reorder=legacy", "--enable-managedby-label", "--enable-managedby-label=false",
		"--load-restrictor LoadRestrictionsRootOnly", "--load-restrictor LoadRestrictionsNone", "--load-restrictor=LoadRestrictionsNone",
		"--enable-helm", "--enable-exec", "--enable-alpha-plugins", "--output /tmp/x", "--reorder", "--reorder none --reorder legacy",
		"-o x", "--reorder\tnone", "--enable-managedby-label=yes", "reorder none", "--reorder=none=x", "--reorder --enable-exec",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := checkBuildOptions(0, raw)
		if err != nil {
			if !IsUnsupported(err) {
				t.Fatalf("checkBuildOptions(%q) failed with %v, not an UnsupportedError", raw, err)
			}
			return
		}
		toks := strings.Fields(raw)
		if strings.Join(out, "\x00") != strings.Join(toks, "\x00") {
			t.Fatalf("checkBuildOptions(%q) = %q, not the options as written", raw, out)
		}
		for i := 0; i < len(out); i++ {
			name, val, hasVal := strings.Cut(out[i], "=")
			spec, ok := allowedBuildOptions[name]
			if !ok {
				t.Fatalf("checkBuildOptions(%q) passed %q", raw, out[i])
			}
			if spec.values == nil {
				continue
			}
			if !hasVal {
				i++
				val = out[i]
			}
			if !spec.values[val] {
				t.Fatalf("checkBuildOptions(%q) passed %s with the value %q", raw, name, val)
			}
		}
	})
}

// FuzzParseSources is the sources parameter: any input either parses to at least one source or is an error.
func FuzzParseSources(f *testing.F) {
	for _, s := range []string{
		"", "[]", "{}", "null", `[{"repoURL":"https://git.example.test/o/r.git","path":"app","targetRevision":"v1"}]`,
		`[{"repoURL":"https://git.example.test/o/r.git","path":"../x"}]`, `[{"repoURL":"x","unknown":1}]`, `[{}] [{}]`,
		`[{"repoURL":"https://charts.example.test","chart":"c","targetRevision":"1.0.0","helm":{"valueFiles":["/etc/passwd"]}}]`,
		`[{"repoURL":"x","ref":"values"},{"repoURL":"y","helm":{"valueFiles":["$values/../x"]}}]`, `[1]`, `[null]`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		srcs, err := ParseSources(raw)
		if err == nil && len(srcs) == 0 {
			t.Fatalf("ParseSources(%q) returned no source and no error", raw)
		}
	})
}
