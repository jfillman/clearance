package traefikhub_test

// The card's premise is that a Traefik Hub customer can point Hub's AuthZEN middleware at Clearance's
// POST /access/v1/evaluation and get Clearance's tiers and structured denials. These tests pin what is true today
// (docs/federate-traefik-hub.md, "Clearance as Hub's PDP"): the bodies below are AuthZEN 1.0 evaluations shaped as
// Traefik's published mapping reference says Hub builds them (subject type and id, action name, resource type and
// id, a context map; https://doc.traefik.io/traefik-hub/api-gateway/reference/routing/http/middlewares/ref-authzen
// and https://doc.traefik.io/traefik-hub/mcp-gateway/guides/authzen-mcp). Hub's exact wire bytes are Unverified.
// When the core gains a profile for a foreign PEP, these tests change with it.

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/decide"
)

func TestHubsDefaultMCPEvaluationIsRefused(t *testing.T) {
	// authzen-mcp's built-in default for tools/call: subject identity/$token.sub, action = the MCP method,
	// context.agent = $token.?client_id; the resource names the tool.
	body := `{"subject":{"type":"identity","id":"alice"},"action":{"name":"tools/call"},
	  "resource":{"type":"tool","id":"transfer_funds"},"context":{"agent":"coding-agent"}}`
	if _, err := decide.DecodeEvaluation(strings.NewReader(body)); err == nil {
		t.Fatal("the core took Hub's default MCP evaluation")
	}
}

func TestTheClosestHubMappingIsStillRefused(t *testing.T) {
	// The closest a customer's mapping can get: Clearance's subject type, action and resource vocabulary. Hub's
	// mapping has no subject.properties, so the subject's kind and tier ceiling are missing, and context.now (an
	// RFC 3339 time the core requires) is not something the documented mapping roots (token, request, params)
	// provide.
	body := `{"subject":{"type":"principal","id":"alice"},"action":{"name":"tool.call"},
	  "resource":{"type":"tool","id":"repo.read"},"context":{}}`
	_, err := decide.DecodeEvaluation(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "subject kind") {
		t.Fatalf("got %v", err)
	}
}
