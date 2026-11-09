package agent

import "encoding/json"

// LiveWaitSpec is the live wait Job's spec, for the scan test in package agent_test.
var LiveWaitSpec = json.RawMessage(liveWaitSpec)

// TestWaitPin is the pin LiveWaitSpec satisfies.
var TestWaitPin = testPin
