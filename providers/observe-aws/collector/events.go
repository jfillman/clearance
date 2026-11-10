// Package collector is observe-aws: the AWS collector (O-4). Three feeds go through one normalizer and one pipeline
// (internal/observe/pipeline):
//
//   - EventBridge: the CloudTrail management events (and the data events on the configured buckets) an
//     EventBridge rule sends to an SQS queue the collector drains, and AWS Config's configuration item changes.
//     Fast, and not signed: such an observation is sourceVerified=false.
//   - The S3 trail: hourly digests read in batches with log-file integrity validation (providers/observe-aws/digest),
//     every file hash-checked before it is extracted. Such an observation is sourceVerified=true.
//   - AWS Config as the reconciler: a configuration item is joined to the CloudTrail event that caused it
//     (reconcile.go), so one change is one exception with the diff and the pointers to its events.
//
// Beside them run the stages G-TF-5 built (providers/observe-aws/detect): the second witness (state-bucket versions no
// apply explains) and the scheduled plan as the drift detector. Health is reported per account (health.go).
package collector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Feed names (integrity.method and Item.Source).
const (
	FeedEventBridge = "eventbridge"
	FeedTrail       = "trail"
	FeedConfig      = "config"

	MethodEventBridge = "eventbridge-delivery"
	MethodDigestChain = "cloudtrail-digest-chain"
	MethodConfig      = "config-item"
)

// Item is one thing a feed delivered, before the reconciler. Acks run once the item has been posted (an SQS delete).
type Item struct {
	Feed     string
	Raw      json.RawMessage // a CloudTrail record
	Config   *ConfigChange   // or a Config configuration item change
	Verified bool            // the feed's integrity proof held (a digest-chain validated trail)
	Method   string
	Received time.Time
	Acks     []func()
}

// ConfigChange is an AWS Config configuration item change.
type ConfigChange struct {
	ID           string
	Account      string
	Region       string
	ResourceType string
	ResourceID   string
	ResourceName string
	ARN          string
	Captured     time.Time
	ChangeType   string
	Changed      map[string]PropChange
	Related      []string // the CloudTrail event ids Config says caused the item (configurationItem.relatedEvents)
	// Status is configurationItemStatus: OK, ResourceDiscovered, ResourceNotRecorded, ResourceDeleted or
	// ResourceDeletedNotRecorded. Created is configurationItem.resourceCreationTime (zero when Config does not say).
	Status  string
	Created time.Time
}

// BaselineAge is how much older than its capture a resource's creation time must be for a ResourceDiscovered item to
// be the recorder's first discovery of something that already existed, not the record of a creation. AWS Config
// uses status ResourceDiscovered for both (a resource it has not seen before), so the status alone proves nothing.
const BaselineAge = time.Hour

// Baseline says the item records a resource that existed before Config began recording it: status ResourceDiscovered,
// no CloudTrail event related to it, and a resource creation time more than BaselineAge before the capture. That is the
// recorder's first discovery, not a change. An item without a creation time cannot be told apart from a creation
// and stays a change; so does a ResourceDiscovered item created just before its capture (a real, new resource).
func (c *ConfigChange) Baseline() bool {
	return c.Status == "ResourceDiscovered" && len(c.Related) == 0 && !c.Created.IsZero() && c.Captured.Sub(c.Created) > BaselineAge
}

// PropChange is one changed property of a configuration item.
type PropChange struct {
	Previous   any    `json:"previous,omitempty"`
	Updated    any    `json:"updated,omitempty"`
	ChangeType string `json:"change_type,omitempty"`
}

// Pointers are the changed properties, sorted: "Configuration.IpPermissions.0 (CREATE)".
func (c *ConfigChange) Pointers() []string {
	out := make([]string, 0, len(c.Changed))
	for k, v := range c.Changed {
		if v.ChangeType != "" {
			k += " (" + v.ChangeType + ")"
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ctView is the part of a CloudTrail record the collector itself reads: the filter, the correlation key, and the
// actor details an observation carries. Attribution is the pipeline's, from the raw record.
type ctView struct {
	ID, Name, Service, Account, Region string
	Time                               time.Time
	ReadOnly                           *bool
	Category, EventType                string
	UserType, Subject, Issuer          string
	SourceIdentity, UserAgent          string
	SessionName                        string
	Bucket                             string
	ErrorCode, ErrorMessage            string
	ClaimGrant, ClaimPlan              string
	Refs                               map[string]bool // identifiers the event names, for the reconciler
	// Request and Response are the record's requestParameters and responseElements, for the diff an event carries when
	// no Config item joins it (requestDiff).
	Request, Response map[string]any
}

var claimRx = regexp.MustCompile(`clearance/grant=([A-Za-z0-9_-]+)(?:;plan=(sha256:[0-9a-fA-F]+))?`)

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func str(v any) string         { s, _ := v.(string); return s }

// parseCT reads a CloudTrail record.
func parseCT(raw []byte) (*ctView, error) {
	var a map[string]any
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("cloudtrail record: %w", err)
	}
	v := &ctView{ID: str(a["eventID"]), Name: str(a["eventName"]), Account: str(a["recipientAccountId"]), Region: str(a["awsRegion"]),
		Category: str(a["eventCategory"]), EventType: str(a["eventType"]), UserAgent: str(a["userAgent"]),
		ErrorCode: str(a["errorCode"]), ErrorMessage: str(a["errorMessage"]), Refs: map[string]bool{}}
	if v.ID == "" || v.Name == "" {
		return nil, fmt.Errorf("cloudtrail record: eventID and eventName are required")
	}
	v.Service = strings.TrimSuffix(str(a["eventSource"]), ".amazonaws.com")
	if ro, ok := a["readOnly"].(bool); ok {
		v.ReadOnly = &ro
	}
	v.Time, _ = time.Parse(time.RFC3339, str(a["eventTime"]))
	ui := obj(a["userIdentity"])
	sc := obj(ui["sessionContext"])
	v.UserType, v.Subject = str(ui["type"]), str(ui["arn"])
	v.Issuer, v.SourceIdentity = str(obj(sc["sessionIssuer"])["arn"]), str(sc["sourceIdentity"])
	if v.UserType == "AssumedRole" || v.UserType == "FederatedUser" {
		if i := strings.LastIndex(v.Subject, "/"); i >= 0 {
			v.SessionName = v.Subject[i+1:]
		}
	}
	if m := claimRx.FindStringSubmatch(v.UserAgent); m != nil {
		v.ClaimGrant, v.ClaimPlan = m[1], m[2]
	}
	rp := obj(a["requestParameters"])
	v.Request, v.Response = rp, obj(a["responseElements"])
	v.Bucket = str(rp["bucketName"])
	collectRefs(v.Refs, rp, 0)
	collectRefs(v.Refs, obj(a["responseElements"]), 0)
	for _, r := range asList(a["resources"]) {
		if arn := str(obj(r)["ARN"]); arn != "" {
			addRef(v.Refs, arn)
		}
	}
	return v, nil
}

func asList(v any) []any { l, _ := v.([]any); return l }

// addRef records an identifier, and its tail (after the last / or :) when it is an ARN.
func addRef(refs map[string]bool, s string) {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, " \t\n") {
		return
	}
	refs[s] = true
	if strings.HasPrefix(s, "arn:") {
		if i := strings.LastIndexAny(s, "/:"); i >= 0 && i+1 < len(s) {
			refs[s[i+1:]] = true
		}
	}
}

func collectRefs(refs map[string]bool, m map[string]any, depth int) {
	if depth > 3 {
		return
	}
	for _, v := range m {
		switch x := v.(type) {
		case string:
			addRef(refs, x)
		case map[string]any:
			collectRefs(refs, x, depth+1)
		case []any:
			for _, y := range x {
				switch z := y.(type) {
				case string:
					addRef(refs, z)
				case map[string]any:
					collectRefs(refs, z, depth+1)
				}
			}
		}
	}
}

// Write says whether the record is a change the collector assesses: not a read, and not made by an AWS service itself.
func (v *ctView) Write() bool {
	if v.ReadOnly != nil && *v.ReadOnly {
		return false
	}
	if v.UserType == "AWSService" || v.EventType == "AwsServiceEvent" {
		return false
	}
	return true
}

// Data says the record is a data event (CloudTrail's eventCategory).
func (v *ctView) Data() bool { return strings.EqualFold(v.Category, "Data") }

// envelope is an EventBridge event as SQS delivers it.
type envelope struct {
	DetailType string          `json:"detail-type"`
	Source     string          `json:"source"`
	Account    string          `json:"account"`
	Region     string          `json:"region"`
	Time       string          `json:"time"`
	Detail     json.RawMessage `json:"detail"`
}

// ParseMessage turns an SQS message body (an EventBridge event) into an Item. A detail-type it does not know is an
// error the caller counts (the rule should not send it); nothing is dropped silently.
func ParseMessage(body []byte, received time.Time) (*Item, error) {
	var e envelope
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("sqs message is not an EventBridge event: %w", err)
	}
	switch e.DetailType {
	case "AWS API Call via CloudTrail", "AWS Service Event via CloudTrail":
		return &Item{Feed: FeedEventBridge, Raw: e.Detail, Method: MethodEventBridge, Received: received}, nil
	case "Config Configuration Item Change":
		c, err := parseConfig(e.Detail, e)
		if err != nil {
			return nil, err
		}
		return &Item{Feed: FeedConfig, Config: c, Method: MethodConfig, Received: received}, nil
	}
	return nil, fmt.Errorf("sqs message has detail-type %q, which the rules do not send", e.DetailType)
}

func parseConfig(detail []byte, e envelope) (*ConfigChange, error) {
	var d struct {
		Diff struct {
			ChangeType string                `json:"changeType"`
			Changed    map[string]rawPropChg `json:"changedProperties"`
		} `json:"configurationItemDiff"`
		Item struct {
			Status       string   `json:"configurationItemStatus"`
			Captured     string   `json:"configurationItemCaptureTime"`
			ResourceType string   `json:"resourceType"`
			ResourceID   string   `json:"resourceId"`
			ResourceName string   `json:"resourceName"`
			ARN          string   `json:"ARN"`
			Region       string   `json:"awsRegion"`
			Account      string   `json:"awsAccountId"`
			Related      []string `json:"relatedEvents"`
			Created      string   `json:"resourceCreationTime"`
		} `json:"configurationItem"`
	}
	if err := json.Unmarshal(detail, &d); err != nil {
		return nil, fmt.Errorf("config item: %w", err)
	}
	it := d.Item
	if it.ResourceID == "" || it.ResourceType == "" {
		return nil, fmt.Errorf("config item: resourceType and resourceId are required")
	}
	c := &ConfigChange{Account: orElse(it.Account, e.Account), Region: orElse(it.Region, e.Region), ResourceType: it.ResourceType,
		ResourceID: it.ResourceID, ResourceName: it.ResourceName, ARN: it.ARN, ChangeType: d.Diff.ChangeType, Related: it.Related,
		Status: it.Status, Changed: map[string]PropChange{}}
	if it.Created != "" {
		if t, err := time.Parse(time.RFC3339, it.Created); err == nil {
			c.Created = t
		} else if t, err := time.Parse("2006-01-02T15:04:05.000Z", it.Created); err == nil {
			c.Created = t
		}
	}
	var err error
	if c.Captured, err = time.Parse(time.RFC3339, it.Captured); err != nil {
		if c.Captured, err = time.Parse("2006-01-02T15:04:05.000Z", it.Captured); err != nil {
			return nil, fmt.Errorf("config item: configurationItemCaptureTime %q", it.Captured)
		}
	}
	for k, p := range d.Diff.Changed {
		c.Changed[k] = PropChange{Previous: p.Previous, Updated: p.Updated, ChangeType: p.ChangeType}
	}
	c.ID = fmt.Sprintf("%s/%s/%s/%s@%s", c.Account, c.Region, c.ResourceType, c.ResourceID, c.Captured.UTC().Format("20060102T150405Z"))
	return c, nil
}

type rawPropChg struct {
	Previous   any    `json:"previousValue"`
	Updated    any    `json:"updatedValue"`
	ChangeType string `json:"changeType"`
}

func orElse(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
