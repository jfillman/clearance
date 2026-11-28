package server

import (
	"net/http"

	"github.com/jfillman/clearance/internal/compat"
	"github.com/jfillman/clearance/internal/store"
)

// VersionResponse is GET /v1/version's answer (N-6b, N-6c).
type VersionResponse struct {
	// Core is this core's release ("" for a development build).
	Core string `json:"core"`
	// Schema is the database's schema as clearance_schema records it; absent on the in-memory store, which has none.
	Schema *store.SchemaInfo `json:"schema,omitempty"`
	// Compat is the compatibility table this binary was built with.
	Compat compat.Table `json:"compat"`
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	out := VersionResponse{Core: s.opt.Version, Compat: compat.Embedded()}
	if sr, ok := s.opt.Store.(store.SchemaReporter); ok {
		info, err := sr.SchemaInfo(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "the schema version could not be read")
			return
		}
		out.Schema = &info
	}
	writeJSON(w, http.StatusOK, out)
}

// providerVersion refuses a request whose Clearance-Provider header names a provider version outside the range this core
// accepts (N-6c): 412 with code provider_version_unsupported. A request without the header is not checked (providers
// that predate it), nor is a program the table has no range for, nor a version that is not X.Y.Z.
func (s *Server) providerVersion(next http.Handler) http.Handler {
	table := compat.Embedded()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get(compat.ProviderHeader); h != "" {
			if program, version, ok := compat.ParseHeader(h); ok {
				if ok, why := table.Accepts(s.opt.Version, program, version); !ok {
					s.log.WarnContext(r.Context(), "provider refused: version outside the accepted range",
						"program", program, "version", version, "core", s.opt.Version)
					writeJSON(w, http.StatusPreconditionFailed, ErrorResponse{Error: why, Code: compat.CodeProviderVersion})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
