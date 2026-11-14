package api

import (
	"encoding/json"
	"strings"
)

// The change list's cursor. A page ends at a change; the next page starts after it in the list's order, which is
// updated_at then id, both descending. The cursor is "<updated_at>,<id>". The older cursor, a bare updated_at, is still
// accepted and means every change strictly older than that time: it drops changes that share the boundary time, which
// is why the list no longer hands one out.
func changeCursor(updatedAt, id string) string { return updatedAt + "," + id }

// splitCursor reads either form. id is empty for the old one.
func splitCursor(after string) (updatedAt, id string) {
	if i := strings.IndexByte(after, ','); i >= 0 {
		return after[:i], after[i+1:]
	}
	return after, ""
}

// cursorAfter is the cursor that continues a list after the change raw (its record JSON).
func cursorAfter(raw json.RawMessage) (string, bool) {
	var last struct {
		ID        string `json:"id"`
		UpdatedAt string `json:"updated_at"`
	}
	if json.Unmarshal(raw, &last) != nil || last.UpdatedAt == "" || last.ID == "" {
		return "", false
	}
	return changeCursor(last.UpdatedAt, last.ID), true
}

// beforeCursor is true when a change (updatedAt, id) comes after the cursor in the list's descending order.
func beforeCursor(updatedAt, id, after string) bool {
	ts, cid := splitCursor(after)
	if cid == "" {
		return updatedAt < ts
	}
	return updatedAt < ts || (updatedAt == ts && id < cid)
}
