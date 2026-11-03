package store

import (
	"encoding/json"

	"github.com/jfillman/clearance/internal/pycompat"
)

// Undelivered is pg.py PgChanges.undelivered's test on one change: its record's deployments hold an element with
// "delivered": false (the jsonb containment the query filters on) and one with a truthy answer and a falsy
// delivered (the Python filter after it). store/pg runs the first in SQL and both here; store/memory runs both here.
func Undelivered(c Change) bool {
	var r struct {
		Deployments []map[string]any `json:"deployments"`
	}
	if json.Unmarshal(c.Record, &r) != nil {
		return false
	}
	contained, pending := false, false
	for _, d := range r.Deployments {
		if v, ok := d["delivered"]; ok && v == false {
			contained = true
		}
		if pycompat.Truthy(d["answer"]) && !pycompat.Truthy(d["delivered"]) {
			pending = true
		}
	}
	return contained && pending
}
