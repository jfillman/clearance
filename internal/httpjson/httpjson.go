// Package httpjson writes the core's JSON responses: one encoder for every handler (gate, review, provenance, the
// GitHub App and the server), so they all write the same bytes (HTML characters unescaped, as Python's json.dumps
// writes them, and a trailing newline).
package httpjson

import (
	"encoding/json"
	"net/http"
)

// Write sends v as the response body with the status code.
func Write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
