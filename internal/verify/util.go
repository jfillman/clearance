package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func short8(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
