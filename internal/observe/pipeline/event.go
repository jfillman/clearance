package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate/render"
)

// RawEvent is one recorded raw event as a collector hands it over: the provider's own document, untouched, and the
// scope it came from. Before is the object as it stood before the change, which a collector with a state service (a
// watch cache) supplies for a Kubernetes event (an audit event carries only the new state).
type RawEvent struct {
	Provider string          `json:"provider"` // kubernetes, aws
	Scope    string          `json:"scope"`    // the cluster, or the account (default: the record's own recipientAccountId)
	Raw      json.RawMessage `json:"raw"`
	Before   json.RawMessage `json:"before,omitempty"`
}

// Owner is an ownerReference.
type Owner struct{ Kind, Name string }

// Event is the normalized, flat event every later stage reads.
type Event struct {
	Provider, Scope, ID string
	Time                time.Time

	Verb, API   string // Kubernetes: the verb and "<verb>.<resource>"; AWS: the event name for both
	Write       bool
	Succeeded   bool
	Code        int    // Kubernetes response code
	ErrorCode   string // AWS errorCode
	Kind        string // Kubernetes kind; AWS: the service (the event source without ".amazonaws.com")
	Namespace   string
	Name        string
	Subresource string
	ResourceID  string // AWS: the resource the request names
	Region      string

	// The actor, as the source verified it (Subject, Type, Issuer, SourceIdentity) and as the actor reported it
	// (SessionName, UserAgent, the claims in the user agent).
	Subject, Type, Issuer, SourceIdentity string
	SessionName, UserAgent                string
	Groups                                []string
	Impersonated                          string
	TaskID                                string
	ClaimGrant, ClaimPlan                 string

	AuditAnnotations map[string]string // Kubernetes audit annotations
	ObjAnnotations   map[string]string // the stored object's annotations (names and values)
	Labels           map[string]string
	Owners           []Owner
	UID              string

	// Before and After are the canonical stored object (server-managed fields and the gate's own annotations
	// removed); the hashes are what a grant lists. Empty when the event has no object, always for a Secret.
	Before, After         map[string]any
	BeforeHash, AfterHash string

	// ExecKey is the execution context the source quotes (a grant, a session): correlation joins on it.
	ExecKey string
	// Monitoring: the operation protects monitoring (set by the pipeline from the rule set and vocabulary).
	Monitoring bool
}

// ErrSkip is Normalize's answer for an event that is not a write (a read, or an audit stage that is not the last):
// it is counted, not assessed.
var ErrSkip = errors.New("not a write")

// Key is the resource's identity within its scope.
func (e *Event) Key() string {
	if e.Provider == AWS {
		return e.Kind + "/" + e.ResourceID
	}
	return e.Kind + "/" + e.Namespace + "/" + e.Name
}

// Normalize flattens a raw event and canonicalizes the stored object. Secrets are never read into the event: a
// Secret's body, before or after, does not leave this function (the observation is Metadata only, observe.Check).
func (rs *RuleSet) Normalize(r RawEvent) (*Event, error) {
	dec := json.NewDecoder(bytes.NewReader(r.Raw))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("raw event: %w", err)
	}
	var e *Event
	var err error
	switch r.Provider {
	case Kubernetes:
		e, err = rs.normalizeKube(raw, r)
	case AWS:
		e, err = rs.normalizeAWS(raw, r)
	default:
		return nil, fmt.Errorf("raw event: provider %q is not one this build normalizes (kubernetes, aws)", r.Provider)
	}
	if err != nil {
		return nil, err
	}
	if e.Scope == "" {
		return nil, errors.New("raw event: no scope (the cluster or account it came from)")
	}
	return e, nil
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func str(v any) string         { s, _ := v.(string); return s }

func strMap(v any) map[string]string {
	m := obj(v)
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

var kubeKinds = map[string]string{
	"configmaps": "ConfigMap", "secrets": "Secret", "deployments": "Deployment", "replicasets": "ReplicaSet", "pods": "Pod",
	"services": "Service", "ingresses": "Ingress", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet",
	"serviceaccounts": "ServiceAccount", "namespaces": "Namespace", "applications": "Application",
	"horizontalpodautoscalers": "HorizontalPodAutoscaler", "certificates": "Certificate", "jobs": "Job", "cronjobs": "CronJob",
	"networkpolicies":                   "NetworkPolicy",
	"validatingwebhookconfigurations":   "ValidatingWebhookConfiguration",
	"mutatingwebhookconfigurations":     "MutatingWebhookConfiguration",
	"validatingadmissionpolicies":       "ValidatingAdmissionPolicy",
	"validatingadmissionpolicybindings": "ValidatingAdmissionPolicyBinding",
	"clusterroles":                      "ClusterRole", "clusterrolebindings": "ClusterRoleBinding", "rolebindings": "RoleBinding", "roles": "Role",
}

func kindOf(resource string, o map[string]any) string {
	if k := str(o["kind"]); k != "" && k != "Status" {
		return k
	}
	if k, ok := kubeKinds[resource]; ok {
		return k
	}
	r := strings.TrimSuffix(resource, "s")
	if r == "" {
		return ""
	}
	return strings.ToUpper(r[:1]) + r[1:]
}

func (rs *RuleSet) normalizeKube(a map[string]any, r RawEvent) (*Event, error) {
	if st := str(a["stage"]); st != "" && st != "ResponseComplete" {
		return nil, ErrSkip
	}
	verb := str(a["verb"])
	switch verb {
	case "create", "update", "patch", "delete", "deletecollection":
	default:
		return nil, ErrSkip
	}
	ref := obj(a["objectRef"])
	user := obj(a["user"])
	e := &Event{Provider: Kubernetes, Scope: r.Scope, ID: str(a["auditID"]), Verb: verb, Write: true,
		Namespace: str(ref["namespace"]), Name: str(ref["name"]), Subresource: str(ref["subresource"]),
		Subject: str(user["username"]), UserAgent: str(a["userAgent"]), AuditAnnotations: strMap(a["annotations"])}
	e.Time = parseTime(str(a["stageTimestamp"]), str(a["requestReceivedTimestamp"]))
	if e.ID == "" || e.Subject == "" {
		return nil, errors.New("kubernetes audit event: auditID and user.username are required")
	}
	for _, g := range asList(user["groups"]) {
		e.Groups = append(e.Groups, str(g))
	}
	if imp := obj(a["impersonatedUser"]); imp != nil {
		e.Impersonated = str(imp["username"])
	}
	extra := obj(user["extra"])
	key := rs.ids.TaskIDExtraKey
	if key == "" {
		key = "task_id"
	}
	if l := asList(extra[key]); len(l) > 0 {
		e.TaskID = str(l[0])
	}
	e.Type = "user"
	switch {
	case strings.HasPrefix(e.Subject, "system:serviceaccount:"):
		e.Type = "serviceaccount"
	case strings.HasPrefix(e.Subject, "system:"):
		e.Type = "system"
	}
	if st := obj(a["responseStatus"]); st != nil {
		if n, ok := st["code"].(json.Number); ok {
			c, _ := n.Int64()
			e.Code = int(c)
		}
	}
	e.Succeeded = e.Code == 0 || (e.Code >= 200 && e.Code < 300)
	resource := str(ref["resource"])
	resp, req := obj(a["responseObject"]), obj(a["requestObject"])
	after := resp
	if str(after["kind"]) == "Status" || after == nil {
		after = nil
		if verb == "create" || verb == "update" {
			after = req
		}
	}
	e.Kind = kindOf(resource, firstObj(after, req))
	e.API = verb + "." + resource
	if e.Name == "" && after != nil {
		e.Name = str(obj(after["metadata"])["name"])
	}
	if e.Namespace == "" && after != nil {
		e.Namespace = str(obj(after["metadata"])["namespace"])
	}
	var before map[string]any
	if len(r.Before) > 0 {
		dec := json.NewDecoder(bytes.NewReader(r.Before))
		dec.UseNumber()
		if err := dec.Decode(&before); err != nil {
			return nil, fmt.Errorf("before: %w", err)
		}
	}
	if verb == "delete" && before == nil && e.Succeeded && str(resp["kind"]) != "Status" {
		before, after = resp, nil // the deleted object is the response
	}
	if verb == "delete" {
		after = nil
	}
	// The stored object's own metadata (never a Secret's body).
	meta := obj(after["metadata"])
	if meta == nil {
		meta = obj(before["metadata"])
	}
	e.ObjAnnotations, e.Labels, e.UID = strMap(meta["annotations"]), strMap(meta["labels"]), str(meta["uid"])
	for _, o := range asList(meta["ownerReferences"]) {
		e.Owners = append(e.Owners, Owner{str(obj(o)["kind"]), str(obj(o)["name"])})
	}
	if strings.EqualFold(e.Kind, "secret") {
		// A Secret is observed at Metadata only: its object, before or after, is not carried, hashed or diffed.
		for k := range e.ObjAnnotations {
			if k == "kubectl.kubernetes.io/last-applied-configuration" {
				delete(e.ObjAnnotations, k) // it holds the body
			}
		}
		return e, nil
	}
	if after != nil {
		e.After = rs.canonicalObject(after)
		e.AfterHash = render.ObjectDigest(render.Doc{Value: e.After})
	}
	if before != nil {
		e.Before = rs.canonicalObject(before)
		e.BeforeHash = render.ObjectDigest(render.Doc{Value: e.Before})
	}
	if g := e.ObjAnnotations[rs.ann.Grant]; g != "" {
		e.ExecKey = "grant:" + g
	}
	return e, nil
}

func firstObj(ms ...map[string]any) map[string]any {
	for _, m := range ms {
		if m != nil {
			return m
		}
	}
	return nil
}

func asList(v any) []any { l, _ := v.([]any); return l }

func parseTime(ss ...string) time.Time {
	for _, s := range ss {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// serverFields are removed from a stored object before it is hashed or diffed: they change without anyone changing
// what was rendered.
var serverFields = []string{"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields", "selfLink",
	"deletionTimestamp", "deletionGracePeriodSeconds"}

var serverAnnotations = []string{"kubectl.kubernetes.io/last-applied-configuration", "deployment.kubernetes.io/revision"}

// canonicalObject is the object as the gate hashes a rendered one: no status, no server-managed metadata, none of the
// gate's own annotations (the stamp, the tree, the release, Argo's tracking id), and no empty annotations map. It
// copies what it changes; the input is not modified.
func (rs *RuleSet) canonicalObject(o map[string]any) map[string]any {
	out := make(map[string]any, len(o))
	for k, v := range o {
		if k == "status" {
			continue
		}
		out[k] = v
	}
	md := obj(o["metadata"])
	if md == nil {
		return out
	}
	m := make(map[string]any, len(md))
	for k, v := range md {
		m[k] = v
	}
	for _, k := range serverFields {
		delete(m, k)
	}
	if ann := obj(md["annotations"]); ann != nil {
		a := make(map[string]any, len(ann))
		for k, v := range ann {
			a[k] = v
		}
		for _, k := range serverAnnotations {
			delete(a, k)
		}
		for _, k := range []string{rs.ann.Grant, rs.ann.Rendered} {
			delete(a, k)
		}
		for _, k := range rs.ann.Strip {
			delete(a, k)
		}
		if len(a) == 0 {
			delete(m, "annotations")
		} else {
			m["annotations"] = a
		}
	}
	out["metadata"] = m
	return out
}

// ---- AWS --------------------------------------------------------------------------------------------------------

var claimRx = regexp.MustCompile(`clearance/grant=([A-Za-z0-9_-]+)(?:;plan=(sha256:[0-9a-fA-F]+))?`)

var awsReadPrefixes = []string{"Get", "List", "Describe", "Lookup", "Head", "BatchGet"}

// resourceKeys are the request parameters that name the resource a CloudTrail record is about, in the order tried.
var resourceKeys = []string{"name", "trailName", "trailARN", "bucketName", "functionName", "roleName", "userName", "groupName",
	"policyArn", "instanceId", "resourceId", "ruleName", "configurationRecorderName", "keyId", "tableName", "clusterName", "DBInstanceIdentifier", "dBInstanceIdentifier"}

func (rs *RuleSet) normalizeAWS(a map[string]any, r RawEvent) (*Event, error) {
	name := str(a["eventName"])
	if name == "" || str(a["eventID"]) == "" {
		return nil, errors.New("cloudtrail record: eventName and eventID are required")
	}
	write := true
	if ro, ok := a["readOnly"].(bool); ok && ro {
		write = false
	}
	for _, p := range awsReadPrefixes {
		if strings.HasPrefix(name, p) {
			write = false
		}
	}
	if !write {
		return nil, ErrSkip
	}
	ui := obj(a["userIdentity"])
	sc := obj(ui["sessionContext"])
	issuer := obj(sc["sessionIssuer"])
	e := &Event{Provider: AWS, Scope: r.Scope, ID: str(a["eventID"]), Verb: name, API: name, Write: true,
		Time:    parseTime(str(a["eventTime"])),
		Subject: str(ui["arn"]), Type: str(ui["type"]), Issuer: str(issuer["arn"]), SourceIdentity: str(ui["sourceIdentity"]),
		UserAgent: str(a["userAgent"]), Region: str(a["awsRegion"]), ErrorCode: str(a["errorCode"])}
	if sc != nil && sourceIdentityIn(sc) != "" && e.SourceIdentity == "" {
		e.SourceIdentity = sourceIdentityIn(sc)
	}
	if e.Scope == "" {
		e.Scope = str(a["recipientAccountId"])
	}
	e.Succeeded = e.ErrorCode == ""
	e.Kind = strings.TrimSuffix(str(a["eventSource"]), ".amazonaws.com")
	if e.Type == "AssumedRole" || e.Type == "FederatedUser" {
		if i := strings.LastIndex(e.Subject, "/"); i >= 0 {
			e.SessionName = e.Subject[i+1:]
		}
	}
	if e.Subject == "" && e.Type == "Root" {
		e.Subject = "root"
	}
	if m := claimRx.FindStringSubmatch(e.UserAgent); m != nil {
		e.ClaimGrant, e.ClaimPlan = m[1], m[2]
	}
	rp := obj(a["requestParameters"])
	for _, k := range resourceKeys {
		if s := str(rp[k]); s != "" {
			e.ResourceID, e.Name = s, s
			break
		}
	}
	if e.ResourceID == "" {
		e.ResourceID = "-"
	}
	switch {
	case e.ClaimGrant != "":
		e.ExecKey = "grant:" + e.ClaimGrant
	case e.Subject != "":
		e.ExecKey = "session:" + e.Subject
	}
	return e, nil
}

func sourceIdentityIn(sc map[string]any) string {
	return str(obj(sc["sessionIssuer"])["sourceIdentity"])
}
