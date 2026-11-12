package argosrc

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// resolveFileOrDirectory is util/io/path resolveFileOrDirectory: a path relative to appPath, or, written with a
// leading slash, to repoRoot; symlinks resolved (at most 10 deep) before the check that it stays inside repoRoot.
func resolveFileOrDirectory(appPath, repoRoot, p string, allowRoot bool) (string, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", errors.New("failed to resolve path")
	}
	full := p
	if !filepath.IsAbs(full) {
		absWork, err := filepath.Abs(appPath)
		if err != nil {
			return "", errors.New("failed to resolve path")
		}
		full = filepath.Join(absWork, full)
	} else {
		full = filepath.Join(absRoot, full)
	}
	full, err = followLinks(full, 10)
	if err != nil {
		return "", errors.New("failed to resolve path")
	}
	full, err = filepath.Abs(full)
	if err != nil {
		return "", errors.New("failed to resolve path")
	}
	need := absRoot
	if !strings.HasSuffix(need, string(os.PathSeparator)) {
		need += string(os.PathSeparator)
	}
	if full+string(os.PathSeparator) == need {
		if !allowRoot {
			return "", errors.New("path resolved to repository root, which is not allowed")
		}
	} else if !strings.HasPrefix(full, need) {
		return "", fmt.Errorf("file %q resolved to outside repository root", p)
	}
	return full, nil
}

func followLinks(p string, depth int) (string, error) {
	t, err := os.Readlink(p)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return p, nil
		}
		return "", err
	}
	if depth == 0 {
		return "", errors.New("maximum nesting level reached")
	}
	if !strings.HasPrefix(t, string(os.PathSeparator)) {
		t = filepath.Join(filepath.Dir(p), t)
	}
	return followLinks(t, depth-1)
}

// resolveValueFile is ResolveValueFilePathOrUrl. A URL value file needs Argo CD's `valuesFileSchemes` setting and a
// fetch the plugin does not make: it is refused, never skipped.
func resolveValueFile(appPath, repoRoot, valueFile string) (string, error) {
	if u, err := url.Parse(valueFile); err == nil && u.Scheme != "" {
		return "", unsupported(0, "a remote value file URL", fmt.Sprintf("scheme %q", u.Scheme))
	}
	return resolveFileOrDirectory(appPath, repoRoot, valueFile, false)
}

// sourcePath is apppathutil.Path: the source's path inside its root, which must stay inside it.
func sourcePath(root, rel string) (string, error) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	cl, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("path %q does not exist in the repository", rel)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if cl != rootReal && !strings.HasPrefix(cl, rootReal+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q resolves outside the repository", rel)
	}
	if st, err := os.Stat(cl); err != nil || !st.IsDir() {
		return "", fmt.Errorf("path %q is not a directory in the repository", rel)
	}
	return cl, nil
}

// checkSymlinks is CheckOutOfBoundsSymlinks: a symbolic link in a checkout that points outside it is refused.
func checkSymlinks(root string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		t, err := filepath.EvalSymlinks(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // a dangling link: Argo CD skips it with a warning
			}
			return err
		}
		if t != rootReal && !strings.HasPrefix(t, rootReal+string(os.PathSeparator)) {
			rel, _ := filepath.Rel(root, p)
			return fmt.Errorf("the source contains an out-of-bounds symlink: %s", rel)
		}
		return nil
	})
}
