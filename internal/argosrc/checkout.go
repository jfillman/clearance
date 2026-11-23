package argosrc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Checkout is a repository already on disk at a known commit: the checkout Argo CD hands the plugin of the source that
// carries it (the Application's own gitops repository). A source that names this repository at this revision is
// copied from it instead of fetched, so the sidecar needs no credential for the Application's own repository, which
// may be private. Argo CD fetched it with its own repository credentials; the plugin never sees them.
type Checkout struct {
	RepoURL        string // the repository exactly as the sources name it (the caller matches spellings)
	TargetRevision string // the revision Argo CD was asked for ("" is HEAD)
	Commit         string // what Argo CD resolved it to: a full 40-hex commit
	Dir            string // the repository's root on disk
}

// sameRevision is whether two requested revisions are the same as written; only "" and HEAD are one. A branch and
// the commit it is at are not: the plugin cannot tell that they agree without asking the remote.
func sameRevision(a, b string) bool {
	norm := func(s string) string {
		if s == "" {
			return "HEAD"
		}
		return s
	}
	return norm(a) == norm(b)
}

// local is the Checkout for this repository and revision, if the caller gave one.
func (o Options) local(repo, rev string) (Checkout, bool) {
	for _, c := range o.Local {
		if c.RepoURL == repo && sameRevision(c.TargetRevision, rev) && sha40Rx.MatchString(c.Commit) && c.Dir != "" {
			return c, true
		}
	}
	return Checkout{}, false
}

// copyCheckout copies a Checkout into a new directory of the render's scratch and returns it: what fetchGit returns
// for a fetch, with the same refusals (submodules, a link that leaves the repository) and the unpack bounds. The copy
// is the render's own, so a step that writes into its tree (kustomize edit, helm dependency build) never writes into
// Argo CD's checkout. A .git entry at the root is not copied. The copy stops when ctx is done.
func (o Options) copyCheckout(ctx context.Context, i int, c Checkout) (string, error) {
	src, err := filepath.EvalSymlinks(c.Dir)
	if err != nil {
		return "", srcErrorf("the Application's checkout: %w", i, err)
	}
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		return "", srcErrorf("the Application's checkout %s is not a directory", i, filepath.Base(src))
	}
	dir, err := os.MkdirTemp(o.Work, "git-")
	if err != nil {
		return "", err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return "", err
	}
	var files int
	var total int64
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || rel == "." {
			return err
		}
		if rel == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if files++; files > maxUnpackFiles {
			return errors.New("the checkout holds too many files")
		}
		target := filepath.Join(dir, rel)
		switch t := d.Type(); {
		case t&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.IsDir():
			return os.Mkdir(target, 0o755)
		case t.IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			if total += info.Size(); total > maxUnpackBytes {
				return errors.New("the checkout is too large")
			}
			mode := os.FileMode(0o644)
			if info.Mode()&0o111 != 0 {
				mode = 0o755
			}
			return copyFile(ctx, p, target, mode, info.Size())
		default:
			return fmt.Errorf("%s is a %s, which is refused", rel, t.Type())
		}
	})
	if err != nil {
		return "", srcErrorf("copy the Application's checkout: %w", i, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".gitmodules")); err == nil {
		return "", unsupported(i, "git submodules", "the repository has a .gitmodules file")
	}
	if err := checkSymlinks(dir); err != nil {
		return "", srcErrorf("%w", i, err)
	}
	return dir, nil
}

// copyFile copies at most size bytes (what the walk counted), in chunks, stopping when ctx is done.
func copyFile(ctx context.Context, from, to string, mode os.FileMode, size int64) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	r := io.LimitReader(in, size)
	for {
		if err := ctx.Err(); err != nil {
			out.Close()
			return err
		}
		n, err := io.CopyN(out, r, 1<<20)
		if errors.Is(err, io.EOF) || (err == nil && n == 0) {
			break
		}
		if err != nil {
			out.Close()
			return err
		}
	}
	return out.Close()
}
