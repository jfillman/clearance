// Package client calls the Clearance core's HTTP API (contract/clearance-core.json): the runtime decision, the
// call's outcome, a provider's own records, the deployment gate and provenance. It is the Go side of what
// clients/python is for the Python gateway, and what Autopilot's Go gateway (A-9) imports. It links nothing of the
// core but the standard library.
//
//	c, err := client.New(client.Options{
//		BaseURL:  "http://clearance-core.clearance-system:8080",
//		Token:    client.FileToken("/var/run/secrets/tokens/clearance"), // re-read per request
//		Provider: "autopilot-gateway",
//	})
//	res, err := c.Evaluate(ctx, &req)
//	switch {
//	case errors.Is(err, client.ErrCoreUnavailable): // the outage policy: fail closed (deny), fast
//	case err != nil:                                // *client.APIError (4xx), client.ErrBadResponse, client.ErrToken
//	case !res.Decision:                             // a deny: res.Context.Rule, Message, Hint
//	default:                                        // allowed: apply res.Context.Spend, act, then c.Outcome(ctx, *res.DecisionID, ...)
//	}
//
// # Errors
//
// Four kinds, told apart with errors.Is and errors.As, none of them a deny (a deny is a result):
//
//   - ErrCoreUnavailable (*UnavailableError): the breaker is open, the connection failed, an attempt timed out, or
//     the core answered 5xx. The caller's outage policy acts on it.
//   - *APIError: a 4xx; the request is wrong or not allowed. Not retried, does not move the breaker.
//   - ErrBadResponse (*ResponseError): an answer that does not decode strictly into the route's type.
//   - ErrToken: the TokenSource failed; nothing was sent.
//
// The caller's own context ending returns its error (context.Canceled or DeadlineExceeded), not
// ErrCoreUnavailable, and does not move the breaker.
//
// # Outage policy
//
// Defaults are the policy decided on 2026-11-02: each attempt has Options.Timeout (250 ms) for the whole exchange;
// a retryable failure is retried Options.Retries (1) time at once; Options.BreakerThreshold (5) consecutive
// unavailable calls open the breaker, which fails every call fast for Options.BreakerCooldown (5 s) and then lets
// one probe through (success closes it, failure opens it again). What is retried depends on whether the call is
// safe to repeat: Evaluate, RegisterChange, Provenance and the probes are retried on any connection failure,
// timeout, 502, 503 or 504; Outcome, Record, Clear and Deny only when nothing can have been acted on (a failed
// dial, or a 503, which the core sends when it did not record). A 500 is unavailable and never retried.
// Healthz and Readyz bypass the breaker.
//
// # Wire types
//
// The request and answer types mirror the core's Go types field for field; a test walks both by reflection, so a
// change to the core's types fails this package's tests until the client follows. Answers are decoded strictly
// (unknown fields are ErrBadResponse) unless Options.AllowUnknownFields.
package client
