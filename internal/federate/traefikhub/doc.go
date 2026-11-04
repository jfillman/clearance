// Package traefikhub is the Traefik Hub adapter (C-9): it reads the decision records and access records Traefik
// Hub's Sovereign Trust Plane keeps, joins them on trace_id, correlates each decision to a task_id where it can,
// and turns each into a federated.decision record for POST /v1/records (provider traefik-hub, every field claimed).
//
// Status: Unverified. It is written against the record format Traefik Labs publishes and tested against the
// published examples; no record from a running Traefik Hub has been read yet (that needs a Hub licence with the
// Transparency Logs feature, or a partner who runs one).
//
// The published format (docs/federate-traefik-hub.md has the full source list):
//
//   - Decision record: one JSON line in the Traefik Hub log (log.filePath, log.format json) per decision of an
//     authzen or authzen-mcp middleware. Fields level, middlewareName, middlewareType, decision (allow, deny or
//     bypass), policy (authzen-mcp only), reason (when set), trace_id (when tracing is enabled),
//     transparency_log_id, gateway_id, time, message; an error field on a deny the mapping caused. It names no
//     user, agent or resource. A key can appear twice when an earlier authentication middleware ran: the last
//     occurrence is the one to read, which is what encoding/json does.
//     https://doc.traefik.io/traefik-hub/api-gateway/observability/transparency-logs
//   - Access record: one JSON line in the access log (accessLog.filePath, accessLog.format json) per request.
//     Traefik's access-log fields (RequestHost, RequestMethod, RequestPath, DownstreamStatus, RouterName,
//     ClientUsername, ...), request_<Header> for each header kept by accessLog.fields.headers, trace_id and TraceId
//     when tracing is enabled, transparency_log_id. It names no policy.
//     https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/
//
// trace_id joins a decision to the access record of the same request. Chained requests that forward traceparent
// share one trace_id, so a trace can hold several of each: a decision is paired with an access record only when its
// trace holds exactly one of each, and a trace's task_id is taken only when every access record that names one
// names the same one.
//
// Correlation to task_id: the default Correlator reads a header the caller sends and Hub keeps in the access record
// (X-Clearance-Task-Id, kept with accessLog.fields.headers.names). The Autopilot gateway, or any client, sets it
// on the calls it makes through Hub. It is a claim, like every field here: a correlated decision carries the
// task_id and source.correlated true, and every record is coverage observed-not-attributed, because Hub's PDP
// authorized the call, not Clearance.
//
// Parsing is bounded: each line is at most MaxLine bytes, a file at most MaxLines lines, and a line that is not a
// JSON object is counted and skipped, never fatal. Decoding is lenient by design (Hub's lines carry many fields
// this adapter does not read); what reaches the core is re-validated there.
package traefikhub
