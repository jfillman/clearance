package store

import "encoding/json"

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
		if truthy(d["answer"]) && !truthy(d["delivered"]) {
			pending = true
		}
	}
	return contained && pending
}

// truthy is Python's bool() on a decoded JSON value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
