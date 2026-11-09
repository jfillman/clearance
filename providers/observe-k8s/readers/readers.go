// Package readers reads the audit logs of managed Kubernetes clusters, where there is no webhook to configure: the
// control plane is the provider's, and its audit log is delivered to the provider's log service. Each reader is a
// fetch (how events are pulled, and how far behind the source it is) and a parser into the one shape the pipeline
// reads, an audit.k8s.io/v1 Event. They all feed the same normalizer, through the same durable queue as the webhook.
//
//	EKS  CloudWatch Logs: the `kube-apiserver-audit` stream of /aws/eks/<cluster>/cluster; the message is the audit event
//	GKE  Cloud Logging: the k8s.io audit log entries (protoPayload), mapped to the audit event shape
//	AKS  the `kube-audit` diagnostic category (or kube-audit-admin): properties.log holds the audit event
//
// Status: the parsers and the polling loop are tested against recorded fixtures only (testdata/). No managed cluster is
// live, and this package has no cloud SDK: the transports (a CloudWatch FilterLogEvents call, a Logging entries.list,
// an Event Hub or Log Analytics read) are the Fetch each deployment supplies. Their latency is real and differs; each
// reader declares it so the gap detector waits for it.
package readers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/providers/observe-k8s/receiver"
)

// Source names a managed-cluster audit source (it is also the health record's source.name).
type Source struct {
	Name string
	// Latency is how far behind the cluster the source typically is: what a watch change waits for its audit event
	// beyond the webhook's own grace. Measured delivery, not a guarantee.
	Latency time.Duration
	// Parse turns one fetched entry into zero or more audit events (zero: not an audit entry, skipped).
	Parse func(entry []byte) ([][]byte, error)
}

// The three sources. Latencies are what the providers document and operators report; each deployment should measure
// its own and set the collector's --latency to it.
var (
	EKS = Source{Name: "k8s-audit-eks", Latency: 2 * time.Minute, Parse: ParseEKS}
	GKE = Source{Name: "k8s-audit-gke", Latency: 2 * time.Minute, Parse: ParseGKE}
	AKS = Source{Name: "k8s-audit-aks", Latency: 5 * time.Minute, Parse: ParseAKS}
)

// ByName finds a source by its short name (eks, gke, aks).
func ByName(n string) (Source, bool) {
	switch strings.ToLower(n) {
	case "eks":
		return EKS, true
	case "gke":
		return GKE, true
	case "aks":
		return AKS, true
	}
	return Source{}, false
}

// Fetcher pulls the next page of entries after cursor ("" the first time): each entry as the service returned it (one
// JSON document), and the cursor to continue from. It returns no entries and the same cursor when there is nothing new.
type Fetcher interface {
	Fetch(ctx context.Context, cursor string) (entries [][]byte, next string, err error)
}

// Sink is the collector's durable queue.
type Sink interface {
	Append(payloads ...[]byte) error
}

// Cursors keeps a reader's position across restarts.
type Cursors interface {
	Load() (string, error)
	Save(string) error
}

// Poll fetches once: it parses every entry, cuts every Secret body out of the events (receiver.SanitizeItems: a
// managed cluster's own policy is not ours to set, so the cut is the only guard), appends them to the queue and then
// moves the cursor. The cursor moves only after the append returned, so a crash re-reads (at-least-once); the core
// de-duplicates on the audit id. It returns how many events it queued.
func Poll(ctx context.Context, src Source, f Fetcher, sink Sink, cur Cursors) (int, error) {
	cursor, err := cur.Load()
	if err != nil {
		return 0, err
	}
	entries, next, err := f.Fetch(ctx, cursor)
	if err != nil {
		return 0, fmt.Errorf("%s: fetching: %w", src.Name, err)
	}
	var raws []json.RawMessage
	for i, e := range entries {
		evs, err := src.Parse(e)
		if err != nil {
			return 0, fmt.Errorf("%s: entry %d: %w", src.Name, i, err)
		}
		for _, ev := range evs {
			raws = append(raws, ev)
		}
	}
	items, _, err := receiver.SanitizeItems(raws)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", src.Name, err)
	}
	if len(items) > 0 {
		if err := sink.Append(items...); err != nil {
			return 0, err
		}
	}
	if next != cursor {
		if err := cur.Save(next); err != nil {
			return len(items), err
		}
	}
	return len(items), nil
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func str(v any) string         { s, _ := v.(string); return s }

func decode(b []byte) (map[string]any, error) {
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// audit checks that a decoded document is an audit.k8s.io Event and re-encodes it.
func audit(m map[string]any) ([][]byte, error) {
	if str(m["auditID"]) == "" || str(m["verb"]) == "" {
		return nil, errors.New("not an audit event (no auditID or verb)")
	}
	b, err := json.Marshal(m)
	return [][]byte{b}, err
}

// ParseEKS reads a CloudWatch Logs event (FilterLogEvents' events[], or a subscription's logEvents[]): its `message`
// is the API server's audit event.
func ParseEKS(entry []byte) ([][]byte, error) {
	m, err := decode(entry)
	if err != nil {
		return nil, err
	}
	msg := str(m["message"])
	if msg == "" {
		return nil, errors.New("a CloudWatch log event has a message")
	}
	ev, err := decode([]byte(msg))
	if err != nil {
		return nil, fmt.Errorf("the message is not JSON: %w", err)
	}
	return audit(ev)
}

// ParseAKS reads a diagnostic log record (an Event Hub record, or a Log Analytics AzureDiagnostics row): only the
// kube-audit and kube-audit-admin categories are audit events; any other category is skipped. The audit event is the
// JSON string in properties.log (log_s in a Log Analytics row).
func ParseAKS(entry []byte) ([][]byte, error) {
	m, err := decode(entry)
	if err != nil {
		return nil, err
	}
	cat := str(m["category"])
	if cat == "" {
		cat = str(m["Category"])
	}
	if cat != "kube-audit" && cat != "kube-audit-admin" {
		return nil, nil
	}
	log := str(obj(m["properties"])["log"])
	if log == "" {
		log = str(m["log_s"])
	}
	if log == "" {
		return nil, errors.New("a kube-audit record has properties.log")
	}
	ev, err := decode([]byte(log))
	if err != nil {
		return nil, fmt.Errorf("properties.log is not JSON: %w", err)
	}
	return audit(ev)
}

// grpcToHTTP maps the codes a Kubernetes audit entry carries in status.code to the HTTP code the audit event has.
var grpcToHTTP = map[int]int{0: 200, 3: 400, 5: 404, 6: 409, 7: 403, 9: 412, 16: 401, 8: 429, 4: 504, 13: 500, 14: 503}

var gkeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true,
	"get": true, "list": true, "watch": true}

// ParseGKE reads a Cloud Logging entry of the k8s.io audit log and maps it to an audit event: the principal is the
// user, the method's last segment the verb, resourceName "<group>/<version>/[namespaces/<ns>/]<resource>[/<name>[/<sub>]]"
// the object, status.code (a gRPC code) the response code, request and response the bodies, and a denied
// authorizationInfo an annotation. An entry of another service is skipped. What GKE records as a Data Access entry
// carries the same fields; what it does not carry (a mutating webhook's patch annotation, the VAP denial's message)
// is simply absent, and attribution says less, never more.
func ParseGKE(entry []byte) ([][]byte, error) {
	m, err := decode(entry)
	if err != nil {
		return nil, err
	}
	p := obj(m["protoPayload"])
	if str(p["serviceName"]) != "k8s.io" {
		return nil, nil
	}
	method := str(p["methodName"])
	i := strings.LastIndex(method, ".")
	if i < 0 || !gkeVerbs[method[i+1:]] {
		return nil, fmt.Errorf("methodName %q has no Kubernetes verb", method)
	}
	verb := method[i+1:]
	group, version, ns, resource, name, sub, err := gkeResource(str(p["resourceName"]))
	if err != nil {
		return nil, err
	}
	code := 200
	if st := obj(p["status"]); st != nil {
		if n, ok := st["code"].(json.Number); ok {
			c, _ := n.Int64()
			if h, ok := grpcToHTTP[int(c)]; ok {
				code = h
			} else {
				code = 500
			}
		}
	}
	ref := map[string]any{"resource": resource, "apiVersion": version}
	if group != "" {
		ref["apiGroup"] = group
	}
	for k, v := range map[string]string{"namespace": ns, "name": name, "subresource": sub} {
		if v != "" {
			ref[k] = v
		}
	}
	ev := map[string]any{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "stage": "ResponseComplete", "auditID": str(m["insertId"]),
		"verb": verb, "user": map[string]any{"username": str(obj(p["authenticationInfo"])["principalEmail"])},
		"userAgent": str(obj(p["requestMetadata"])["callerSuppliedUserAgent"]), "objectRef": ref, "responseStatus": map[string]any{"code": code},
		"stageTimestamp": str(m["timestamp"])}
	if ev["auditID"] == "" || str(ev["stageTimestamp"]) == "" || str(obj(ev["user"])["username"]) == "" {
		return nil, errors.New("a k8s.io audit entry has insertId, timestamp and principalEmail")
	}
	if r := p["request"]; r != nil {
		ev["requestObject"], ev["level"] = r, "RequestResponse"
	}
	if r := p["response"]; r != nil {
		ev["responseObject"], ev["level"] = r, "RequestResponse"
	}
	if az, ok := p["authorizationInfo"].([]any); ok {
		for _, a := range az {
			if am := obj(a); am["granted"] == false {
				ev["annotations"] = map[string]any{"authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": str(am["permission"])}
			}
		}
	}
	return audit(ev)
}

func gkeResource(rn string) (group, version, ns, resource, name, sub string, err error) {
	parts := strings.Split(rn, "/")
	if len(parts) < 3 {
		return "", "", "", "", "", "", fmt.Errorf("resourceName %q is <group>/<version>/<resource>...", rn)
	}
	group, version = parts[0], parts[1]
	if group == "core" {
		group = ""
	}
	rest := parts[2:]
	if rest[0] == "namespaces" && len(rest) >= 3 { // namespaced: namespaces/<ns>/<resource>...
		ns, rest = rest[1], rest[2:]
	}
	resource = rest[0]
	if len(rest) > 1 {
		name = rest[1]
	}
	if len(rest) > 2 {
		sub = rest[2]
	}
	return group, version, ns, resource, name, sub, nil
}

// FileFetcher reads a source's entries from a JSON-lines file that something else keeps appending to (a log shipper
// writing the cloud's export to a volume, an `aws logs tail` or `az monitor` export): one entry per line, the cursor
// is the number of lines already read. It is the one transport this package has; it is what the fixtures exercise.
type FileFetcher struct {
	Path string
	Max  int // lines per fetch (default 500)
}

// Fetch returns the lines after the cursor.
func (f FileFetcher) Fetch(_ context.Context, cursor string) ([][]byte, string, error) {
	n := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &n); err != nil || n < 0 {
			return nil, cursor, fmt.Errorf("cursor %q is a line count", cursor)
		}
	}
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, cursor, nil
	}
	if err != nil {
		return nil, cursor, err
	}
	max := f.Max
	if max <= 0 {
		max = 500
	}
	all := strings.Split(string(b), "\n")
	if len(all) > 0 && all[len(all)-1] == "" {
		all = all[:len(all)-1]
	} else if len(all) > 0 {
		all = all[:len(all)-1] // a last line without its newline is still being written
	}
	if n > len(all) {
		n = 0 // the file was rotated: start again
	}
	var out [][]byte
	for _, l := range all[n:] {
		if len(out) == max {
			break
		}
		n++
		if strings.TrimSpace(l) != "" {
			out = append(out, []byte(l))
		}
	}
	return out, fmt.Sprint(n), nil
}

// FileCursor keeps a cursor in a file, written atomically.
type FileCursor struct{ Path string }

// Load reads the cursor ("" when there is none).
func (c FileCursor) Load() (string, error) {
	b, err := os.ReadFile(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

// Save writes the cursor.
func (c FileCursor) Save(s string) error {
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}
