// Package decide is Clearance's runtime decision: a pure function from an AuthZEN 1.0 Access Evaluation to a
// decision with its rule id, hint, the spend the caller must apply and the record fields to write. It ports
// policy.py, tiers.py, scope.py, limits.py's narrowing, session.py's spawn checks, modelproxy.py's model decision
// and the rule set; the Hangar pack (packs/hangar) ports clearance.packs.hangar. The engine holds no session:
// the request's context carries every piece of state the decision reads, and `now`, so Decide does no I/O and
// reads no clock.
//
// # Request
//
// R-1d serves this at POST /access/v1/evaluation. Decoding is strict (DecodeEvaluation: unknown fields, trailing
// data and wrong types are errors; at most MaxRequestBytes).
//
//	{
//	  "subject":  {"type": "principal", "id": "user:alice",
//	               "properties": {"kind": "user", "tier_ceiling": 1, "acting_as": "..."}},
//	  "action":   {"name": "tool.call" | "session.spawn" | "session.open" | "model.call",
//	               "properties": {"args": {...},            // tool.call, session.spawn
//	                              "est_tokens": 1000,       // model.call
//	                              "limits": {...},          // session.open: requested limits as sent
//	                              "task_id": "t-..", "trigger": "cron"}},   // session.open
//	  "resource": {"type": "tool" | "model" | "agent", "id": "repo.pr.open"},
//	  "context":  {"now": "2026-09-26T12:00:00Z",
//	               "session_id": "s-..",                     // the session the caller named
//	               "session": {id, principal, agent, task_id, parent_id, depth, limits, used, reserved,
//	                           expires_at, closed, tripped, denials},   // absent: no such session
//	               "scope": {agent_kind, deny_paths, repos_allow, api_allow, field_deny, field_allow, profile},
//	               "agent": {name, kind, identity_type, service_account, limits},  // open; spawn's child
//	               "new_session_id": "s-..",                 // the id the caller gives the session it opens
//	               "hold": {by, until, reason},              // a triggered open: the active hold
//	               "live": {...session...},                  // a triggered open: the live session to dedupe onto
//	               "models": {"routes": ["claude-sonnet-5"]}}}  // model.call; absent: no model routes
//
// Limits are limits.Limits.as_dict's shape (tier_ceiling "T1", network "clearance+model", compute "small").
// Integers are exact at any size (Int), as Python's are, so an unbounded budget fails closed the same way.
//
// # Response
//
//	{"decision": false,
//	 "context": {"rule": "R014", "name": "repo-not-allowed", "message": "...", "hint": "...", "tier": 1,
//	             "problems": [{pointer, rule, message, hint}],         // R021's GP-SCOPE findings
//	             "spend": {"tool_calls": 1, "github_calls": 4, "open_prs": 1, "children": 1,
//	                       "reserve": {...budgets...},                  // spawn: reserved on the parent
//	                       "denial": true, "trip": "5 denied calls", "trip_tree": "tripwire: k8s.exec"},
//	             "grant": {session, task_id, principal, agent, parent, depth, limits, expires_at, deduped},
//	             "policy": {"bundle": "clearance-core+hangar", "version": "..."}}}
//
// Spend is what the gateway applies to the request's session when it acts on the decision: add the counters to
// used, add reserve to reserved, count a denial, trip the breaker with trip (if not already tripped), and trip
// every descendant with "parent tripped: <trip_tree>". An allowed tool call is charged before its handler runs, so
// a spawn the handler refuses still carries the call's tool_calls with its denial, as in dispatch.py.
//
// # Actions
//
//	tool.call      Gateway.call: R004 for an unknown session, else Policy.build_context and the rules, first
//	               match wins (R000 on any evaluation error).
//	session.spawn  a run.spawn call: the tool call's rules, then Gateway._spawn: R003 unknown agent, R008 bad
//	               requested limits, R016 parent expired/tripped, depth over 3, children budget, no time left;
//	               R007 a widening. The child is cut from what the parent has left after this call's charge.
//	session.open   Gateway.open_session (R003, R001, R008, R007) and open_triggered (R003, R001, R024 hold,
//	               dedupe onto a live session).
//	model.call     ModelProxy._decide: M001-M007; M006 with no record when the deployment has no model routes.
//
// # Rules
//
// Rules are data (core.json, and each pack's own file): id, name, CEL expression, message, hint and order. New
// compiles them once with cel-go against typed variables (tool.name string, tool.tier int, effective.tools
// list(string), ctx.* bool or int, ...), so a rule that does not compile, is not a bool, reads an undeclared
// field, or whose worst-case cost estimate is over MaxRuleCost fails the load; each evaluation is also cut off
// at MaxRuleCost. A pack (Pack) adds tools, rules placed among the core ones by order, the ctx.* variables its
// Context computes, and a Decide for structured decisions (R021).
//
// # Records
//
// RecordFields gives the event the Python gateway appends for the decision (dispatch.py _audit, _deny_open,
// the unknown-session record; modelproxy.py), envelope excluded. Arguments are hashed (args_sha256 is
// internal/canon's ArgsDigest), never stored. For an allowed tool call result is "ok"; the call's real outcome
// and effect are the caller's to record.
//
// # Fidelity
//
// Python semantics the decision depends on are reproduced exactly: dict order and key equality, True == 1 == 1.0,
// repr in messages, str.lower/strip/len, `$` before a final newline in re.match, fnmatch, posixpath.normpath,
// PyYAML's YAML 1.1 safe_load (internal/pyyaml), json.dumps lengths (internal/pycompat holds those helpers;
// internal/scope is scope.py). The golden corpus (testdata/golden, recorded by
// tools/golden/record.py over the whole Python test suite and the fixture agents' calls) replays through this
// package with identical decisions, rule ids, names, messages, hints, tiers, problems, spend, grants and record
// fields; CEL_DIFFERENCES.md lists where cel-python and cel-go part (only for ill-typed contexts a request
// cannot carry) and where the Go engine fails closed on input the Python one raises on.
package decide
