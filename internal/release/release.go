// Package release holds the clearance release version and its notes. The version is the repository's VERSION file
// (one line, X.Y.Z): the tag vX.Y.Z names it, the release workflow checks the two agree, and tools/pyclient writes it
// into the Python client's _version.py. The notes are the version's section of CHANGELOG.md, which the release
// workflow publishes as the GitHub Release's notes (tools/releasenotes).
package release

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// VersionPath and ChangelogPath are relative to the module root.
const (
	VersionPath   = "VERSION"
	ChangelogPath = "CHANGELOG.md"
)

var versionRx = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?(\.dev[0-9]+)?$`)

// ParseVersion is the version a VERSION file holds: one X.Y.Z line (a trailing newline is fine).
func ParseVersion(b []byte) (string, error) {
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("VERSION is empty")
	}
	if strings.ContainsAny(v, "\r\n") || !versionRx.MatchString(v) {
		return "", fmt.Errorf("VERSION: %q is not X.Y.Z", v)
	}
	return v, nil
}

// Version reads root/VERSION.
func Version(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, VersionPath))
	if err != nil {
		return "", err
	}
	return ParseVersion(b)
}

// Notes is the body of the changelog's `## [version]` section, trimmed, without its heading and without the link
// references at the foot. ok is false when there is no such section or it is empty.
func Notes(changelog, version string) (string, bool) {
	head := regexp.MustCompile(`^## \[` + regexp.QuoteMeta(strings.TrimPrefix(version, "v")) + `\](\s|$)`)
	foot := regexp.MustCompile(`^\[[^\]]+\]: `)
	var out []string
	inside := false
	for _, line := range strings.Split(changelog, "\n") {
		if strings.HasPrefix(line, "## ") {
			if inside {
				break
			}
			inside = head.MatchString(line)
			continue
		}
		if inside {
			if foot.MatchString(line) {
				break
			}
			out = append(out, line)
		}
	}
	body := strings.TrimSpace(strings.Join(out, "\n"))
	return body, body != ""
}

// datedRx is a released section's heading: `## [X.Y.Z] - YYYY-MM-DD`.
func datedRx(version string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^## \[` + regexp.QuoteMeta(version) + `\] - \d{4}-\d{2}-\d{2}$`)
}

// HasDatedSection reports whether the changelog has `## [version] - YYYY-MM-DD`.
func HasDatedSection(changelog, version string) bool {
	return datedRx(version).MatchString(changelog)
}
