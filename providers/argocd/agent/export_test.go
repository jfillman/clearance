package agent

import "encoding/json"

// LiveWaitSpec is the live wait Job's spec, for the scan test in package agent_test.
var LiveWaitSpec = json.RawMessage(liveWaitSpec)

// TestWaitPin is the pin LiveWaitSpec satisfies.
var TestWaitPin = testPin

// SetActiveGrantsPage sets the list page size for a test and returns the old one.
func SetActiveGrantsPage(n int) int { old := activeGrantsPage; activeGrantsPage = n; return old }

// SetMaxPendingBytes sets the exemption-record queue's byte bound for a test and returns the old one.
func SetMaxPendingBytes(n int) int { old := MaxPendingBytes; MaxPendingBytes = n; return old }

// SetMaxStateBytes sets the serialized-state bound a queued record may reach, for a test, and returns the old one.
func SetMaxStateBytes(n int) int { old := MaxStateBytes; MaxStateBytes = n; return old }
