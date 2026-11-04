package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/token"
)

// -- the signed grant feed (C-10) -----------------------------------------------------------------------------------

// GrantFeed is GET /v1/grant-feeds/{cluster}: the cluster's signed grant feed as the core stored it, and the tokens
// it lists. A grant-sync agent verifies Feed (token.VerifyFeed: the core's key, this cluster, fresh, not older than
// the last it accepted), then checks that Tokens are exactly the feed's entries (token.Feed.Match) and verifies
// each token, before it touches a single grant (docs/gate.md, The signed grant feed).
type GrantFeed struct {
	Cluster   string           `json:"cluster"`
	Seq       int64            `json:"seq"`
	KeyID     string           `json:"key_id"`
	IssuedAt  string           `json:"issued_at"`
	ExpiresAt string           `json:"expires_at"`
	Feed      token.Envelope   `json:"feed"`
	Tokens    []gate.FeedToken `json:"tokens"`
}

// clusterName is what a cluster path segment may be.
var clusterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func (s *Server) getGrantFeed(w http.ResponseWriter, r *http.Request, v *Viewer) {
	cluster := r.PathValue("cluster")
	if !clusterName.MatchString(cluster) {
		writeError(w, 400, "cluster is a cluster name")
		return
	}
	if v.Role == RoleFeed && !v.FeedOf(cluster) {
		writeError(w, 403, fmt.Sprintf("%s reads the grant feed of %s only", v.Person, strings.Join(v.Clusters, ", ")))
		return
	}
	row, err := s.opt.Store.Feed(r.Context(), cluster)
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if row == nil {
		writeError(w, 404, "no grant feed for "+cluster+" (the core signs one once a change on it is cleared)")
		return
	}
	out := GrantFeed{Cluster: row.Cluster, Seq: row.Seq, KeyID: row.KeyID,
		IssuedAt: row.IssuedAt.UTC().Format(time.RFC3339), ExpiresAt: row.ExpiresAt.UTC().Format(time.RFC3339),
		Tokens: []gate.FeedToken{}}
	if err := json.Unmarshal(row.Envelope, &out.Feed); err != nil {
		s.readFailed(w, r, fmt.Errorf("api: the stored grant feed: %w", err))
		return
	}
	if err := json.Unmarshal(row.Tokens, &out.Tokens); err != nil {
		s.readFailed(w, r, fmt.Errorf("api: the stored grant feed's tokens: %w", err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

// -- GitHub App installations ---------------------------------------------------------------------------------------

// InstallationList is GET /v1/github/installations.
type InstallationList struct {
	Items []Installation `json:"items"`
}

var installationID = regexp.MustCompile(`^[0-9]{1,20}$`)

// InstallationPrincipal is the principal the records name an installation by: app:<id>.
func InstallationPrincipal(id string) string { return "app:" + id }

func newInstallation(principal string) *Installation {
	return &Installation{ID: strings.TrimPrefix(principal, "app:"), Principal: principal, Status: "active",
		Records: map[string]int64{}, Repos: []string{}, FirstSeq: -1}
}

// add folds in one tool's records: how many, and their seq and ts bounds.
func (in *Installation) add(tool string, n, first, last int64, firstTS, lastTS string) {
	in.Records[tool] += n
	if in.FirstSeq < 0 || first < in.FirstSeq {
		in.FirstSeq = first
	}
	if last > in.LastSeq {
		in.LastSeq = last
	}
	if firstTS != "" && (in.FirstTS == "" || firstTS < in.FirstTS) {
		in.FirstTS = firstTS
	}
	if lastTS > in.LastTS {
		in.LastTS = lastTS
	}
}

// last reads the installation's last app.installation record: its account (target) and its result,
// "<action>: <n> repositories" (provenance.RecordInstallation).
func (in *Installation) last(account *string, result string) {
	in.Account = account
	if action, _, ok := strings.Cut(result, ":"); ok && action != "" {
		in.Action = &action
		switch action {
		case "deleted":
			in.Status = "removed"
		case "suspend":
			in.Status = "suspended"
		}
	}
}

func (s *Server) listInstallations(w http.ResponseWriter, r *http.Request, _ *Viewer) {
	items, err := s.opt.Store.Installations(r.Context())
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	writeJSON(w, 200, InstallationList{Items: items})
}

// installationOf reads the installation query parameter: "" or an installation id.
func installationOf(q map[string]string) (string, *apiError) {
	id := strings.TrimSpace(q["installation"])
	if id != "" && !installationID.MatchString(id) {
		return "", errorf(400, "installation is a GitHub App installation id")
	}
	return id, nil
}
