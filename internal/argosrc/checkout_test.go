package argosrc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ownRepo   = "https://git.example.invalid/acme/gitops.git" // a private repository: the sidecar cannot fetch it
	ownCommit = "0123456789abcdef0123456789abcdef01234567"
)

// noCredential answers a fetch of ownRepo the way git does on a private repository with no credential.
func noCredential(_ string, name string, args []string) ([]byte, bool, error) {
	if name == "git" && len(args) > 1 && strings.Contains(strings.Join(args, " "), "git.example.invalid") {
		return nil, true, errors.New("exit status 128: fatal: could not read Username for 'https://git.example.invalid': terminal prompts disabled")
	}
	return nil, false, nil
}

// ownCheckout is the directory Argo CD hands the plugin: the repository's files, and a .git the copy leaves out.
func ownCheckout(t *testing.T) string {
	dir := t.TempDir()
	write(t, dir, "apps/base.yaml", "color: violet\n")
	write(t, dir, "apps/dev.yaml", "size: m\n")
	write(t, dir, ".git/HEAD", "ref: refs/heads/main\n")
	return dir
}

func fetchedRepos(r *recorder) []string {
	var out []string
	for _, c := range r.calls {
		if c[0] == "git" && indexOf(c, "fetch") >= 0 {
			out = append(out, c[len(c)-2])
		}
	}
	return out
}

// The Application's own repository at the carrier's revision is rendered from Argo CD's checkout, and its $ref value
// files resolve against it; the chart's repository, a different one, is still fetched.
func TestTheOwnRepositoryIsCopiedFromTheCheckoutNotFetched(t *testing.T) {
	chart := gitRepo(t, demoChart())
	co := ownCheckout(t)
	r := &recorder{fake: noCredential}
	o := opts(t, r)
	o.Local = []Checkout{{RepoURL: ownRepo, TargetRevision: "main", Commit: ownCommit, Dir: co}}
	need(t, "helm")
	res, err := Render(context.Background(), o, Request{AppName: "own", Namespace: "ns", Sources: []Source{
		{RepoURL: ownRepo, TargetRevision: "main", Path: ".", Ref: "appsrc", Directory: &Directory{Exclude: "*"}},
		{RepoURL: chart, Path: "chart", Helm: &Helm{ValueFiles: []string{"$appsrc/apps/base.yaml", "$appsrc/apps/dev.yaml", "$appsrc/apps/absent.yaml"}, IgnoreMissingValueFiles: true}},
	}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	has(t, res, `color: "violet"`, `size: "m"`)
	if got := fetchedRepos(r); len(got) != 1 || got[0] != chart {
		t.Fatalf("fetched %v, want only the chart's repository", got)
	}
	if len(res.Sources) != 2 || !res.Sources[0].Checkout || res.Sources[0].Resolved != ownCommit || res.Sources[1].Checkout {
		t.Fatalf("provenance %+v", res.Sources)
	}
	// The copy is the render's own: nothing was written into Argo CD's checkout, and its .git was not copied.
	if ents, _ := os.ReadDir(co); len(ents) != 2 {
		t.Fatalf("the checkout was changed: %v", ents)
	}
	matches, _ := filepath.Glob(filepath.Join(o.Work, "git-*", ".git"))
	if len(matches) != 0 {
		t.Fatalf("the copy holds %v", matches)
	}
}

// Another revision of the own repository, or another spelling of it the caller did not offer, is fetched as before,
// and a private repository fails as it did.
func TestTheOwnRepositoryAtAnotherRevisionIsFetched(t *testing.T) {
	chart := gitRepo(t, demoChart())
	for name, src := range map[string]Source{
		"another revision": {RepoURL: ownRepo, TargetRevision: "release-1", Ref: "appsrc"},
		"a commit":         {RepoURL: ownRepo, TargetRevision: ownCommit, Ref: "appsrc"},
		"another spelling": {RepoURL: strings.TrimSuffix(ownRepo, ".git"), TargetRevision: "main", Ref: "appsrc"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &recorder{fake: noCredential}
			o := opts(t, r)
			o.Local = []Checkout{{RepoURL: ownRepo, TargetRevision: "main", Commit: ownCommit, Dir: ownCheckout(t)}}
			_, err := Render(context.Background(), o, Request{AppName: "own", Namespace: "ns", Sources: []Source{
				src, {RepoURL: chart, Path: "chart", Helm: &Helm{ValueFiles: []string{"$appsrc/apps/base.yaml"}}}}})
			if err == nil || !IsSources(err) || !strings.Contains(err.Error(), "could not read Username") || !strings.Contains(err.Error(), "fetch") {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// "" and HEAD are one revision; a branch is not the commit it is at.
func TestSameRevision(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"", "HEAD", true}, {"main", "main", true}, {" main ", "main", false}, {"main", "Main", false}, {"main", ownCommit, false}, {"", "main", false}} {
		if got := sameRevision(c.a, c.b); got != c.want {
			t.Errorf("sameRevision(%q, %q) = %v", c.a, c.b, got)
		}
	}
	// a Checkout with no full commit is never used
	o := Options{Local: []Checkout{{RepoURL: ownRepo, TargetRevision: "main", Commit: "main", Dir: "/x"}}}
	if _, ok := o.local(ownRepo, "main"); ok {
		t.Fatal("a Checkout without a commit was used")
	}
}

// The copy keeps fetchGit's refusals: a link out of the repository and submodules.
func TestTheCheckoutCopyKeepsTheFetchRefusals(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "token")
	write(t, filepath.Dir(outside), "token", "secret\n")
	for name, setup := range map[string]func(dir string){
		"a link out": func(dir string) {
			if err := os.Symlink(outside, filepath.Join(dir, "apps", "leak.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"submodules": func(dir string) { write(t, dir, ".gitmodules", "[submodule \"x\"]\n") },
	} {
		t.Run(name, func(t *testing.T) {
			co := ownCheckout(t)
			setup(co)
			o := Options{Run: (&recorder{fake: noCredential}).run, Work: t.TempDir()}
			if _, err := o.copyCheckout(context.Background(), 1, Checkout{RepoURL: ownRepo, TargetRevision: "main", Commit: ownCommit, Dir: co}); err == nil || !IsSources(err) {
				t.Fatalf("err %v", err)
			}
		})
	}
	// an in-repository link is kept, as a link
	co := ownCheckout(t)
	if err := os.Symlink("base.yaml", filepath.Join(co, "apps", "alias.yaml")); err != nil {
		t.Fatal(err)
	}
	o := Options{Work: t.TempDir()}
	dir, err := o.copyCheckout(context.Background(), 1, Checkout{RepoURL: ownRepo, TargetRevision: "main", Commit: ownCommit, Dir: co})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "apps", "alias.yaml")); err != nil || string(b) != "color: violet\n" {
		t.Fatalf("%q %v", b, err)
	}
}

// A render whose deadline has passed stops copying.
func TestTheCheckoutCopyStopsWhenTheRenderIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := Options{Work: t.TempDir()}
	if _, err := o.copyCheckout(ctx, 1, Checkout{RepoURL: ownRepo, TargetRevision: "main", Commit: ownCommit, Dir: ownCheckout(t)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
