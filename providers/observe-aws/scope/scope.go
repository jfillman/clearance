// Package scope is the first-release filter of what observe-aws evaluates (O-4). A CloudTrail write is in one of
// three states:
//
//   - evaluated: IAM, CloudTrail and Config configuration, security groups, S3 bucket policies and public access, KMS,
//     and the data events (PutObject, DeleteObject) of the configured state and artifact buckets;
//   - planned: VPC routing, Secrets Manager, Lambda configuration, EKS access and RDS (the second wave; named as not
//     evaluated until Filter.MaxWave is 2);
//   - not evaluated: everything else, counted per service and named.
//
// What the filter does not evaluate is never silent: Counts are kept per area, and Statement is the sentence the
// collector's health record and the packet carry.
package scope

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Decision is the filter's answer for one event.
type Decision struct {
	Evaluated bool
	Wave      int    // 1 or 2 for a classified area, 0 for one the filter does not know
	Area      string // the area's name, or "<service> (not classified)"
}

type area struct {
	name string
	wave int
}

// Always-not-evaluated, named in every statement: no control over them is claimed.
var NeverEvaluated = []string{
	"SSM session contents (a session's start and stop are events; what was typed is not)",
	"database content (data-plane reads and writes of RDS, DynamoDB and other databases)",
	"S3 object content and data events of buckets that are not configured as state or artifact buckets",
	"services outside the first-release list (partially covered: their management events are counted, not assessed)",
}

// Filter classifies events. Safe for concurrent use.
type Filter struct {
	MaxWave     int      // 1 (default): the first-release scope. 2 adds the second wave.
	DataBuckets []string // the state, artifact and secrets buckets whose data events are evaluated

	mu     sync.Mutex
	counts map[string]int
}

func (f *Filter) maxWave() int {
	if f.MaxWave == 0 {
		return 1
	}
	return f.MaxWave
}

var (
	sgVerbs       = []string{"AuthorizeSecurityGroup", "RevokeSecurityGroup", "CreateSecurityGroup", "DeleteSecurityGroup", "ModifySecurityGroupRules", "UpdateSecurityGroupRuleDescriptions", "ModifyNetworkInterfaceAttribute"}
	s3PolicyNames = map[string]bool{"PutBucketPolicy": true, "DeleteBucketPolicy": true, "PutBucketAcl": true, "PutPublicAccessBlock": true,
		"DeletePublicAccessBlock": true, "PutBucketOwnershipControls": true, "DeleteBucketOwnershipControls": true, "CreateBucket": true,
		"DeleteBucket": true, "PutBucketEncryption": true, "DeleteBucketEncryption": true, "PutBucketVersioning": true,
		"PutBucketCors": true, "PutBucketWebsite": true, "PutBucketLogging": true, "PutBucketReplication": true,
		"PutBucketLifecycle": true, "PutBucketLifecycleConfiguration": true, "PutBucketNotification": true, "PutBucketNotificationConfiguration": true}
	s3ControlNames = map[string]bool{"PutPublicAccessBlock": true, "DeletePublicAccessBlock": true, "PutAccessPointPolicy": true,
		"DeleteAccessPointPolicy": true, "CreateAccessPoint": true, "DeleteAccessPoint": true, "PutMultiRegionAccessPointPolicy": true}
	s3DataNames = map[string]bool{"PutObject": true, "DeleteObject": true, "DeleteObjects": true, "CopyObject": true,
		"CompleteMultipartUpload": true, "PutObjectAcl": true, "DeleteObjectVersion": true}
	routeVerbs = []string{"CreateRoute", "ReplaceRoute", "DeleteRoute", "CreateRouteTable", "DeleteRouteTable", "AssociateRouteTable",
		"DisassociateRouteTable", "ReplaceRouteTableAssociation", "CreateTransitGatewayRoute", "ReplaceTransitGatewayRoute", "DeleteTransitGatewayRoute"}
	lambdaConfig = []string{"UpdateFunctionConfiguration", "UpdateFunctionCode", "AddPermission", "RemovePermission", "CreateFunctionUrlConfig",
		"UpdateFunctionUrlConfig", "DeleteFunctionUrlConfig", "PutFunctionConcurrency", "DeleteFunction", "CreateFunction", "UpdateFunctionEventInvokeConfig",
		"PublishLayerVersion", "CreateEventSourceMapping", "UpdateEventSourceMapping", "DeleteEventSourceMapping"}
	eksAccess = []string{"CreateAccessEntry", "UpdateAccessEntry", "DeleteAccessEntry", "AssociateAccessPolicy", "DisassociateAccessPolicy",
		"UpdateClusterConfig", "CreateCluster", "DeleteCluster", "AssociateIdentityProviderConfig", "DisassociateIdentityProviderConfig",
		"CreatePodIdentityAssociation", "UpdatePodIdentityAssociation", "DeletePodIdentityAssociation"}
)

func hasAny(name string, list []string) bool {
	for _, v := range list {
		if name == v {
			return true
		}
	}
	return false
}

// classify names the area of an event, wave 0 when the filter does not know the service. service is the event
// source without ".amazonaws.com"; data says the event is an S3 data event on a configured bucket.
func classify(service, name string, data bool) area {
	switch service {
	case "iam":
		return area{"IAM", 1}
	case "cloudtrail":
		return area{"CloudTrail configuration", 1}
	case "config":
		return area{"AWS Config configuration", 1}
	case "kms":
		return area{"KMS", 1}
	case "events":
		// EventBridge rules are the collector's own feed: their disabling is an operation on monitoring.
		if strings.HasSuffix(name, "Rule") || strings.HasSuffix(name, "Targets") {
			return area{"EventBridge rules (monitoring feed)", 1}
		}
	case "ec2":
		for _, v := range sgVerbs {
			if strings.HasPrefix(name, v) {
				return area{"security groups", 1}
			}
		}
		if hasAny(name, routeVerbs) {
			return area{"VPC routing", 2}
		}
	case "s3":
		if data && s3DataNames[name] {
			return area{"S3 data events (state and artifact buckets)", 1}
		}
		if s3PolicyNames[name] {
			return area{"S3 policies and public access", 1}
		}
	case "s3-control":
		if s3ControlNames[name] {
			return area{"S3 policies and public access", 1}
		}
	case "secretsmanager":
		return area{"Secrets Manager", 2}
	case "lambda":
		if hasAny(name, lambdaConfig) {
			return area{"Lambda configuration", 2}
		}
	case "eks":
		if hasAny(name, eksAccess) {
			return area{"EKS access", 2}
		}
	case "rds":
		return area{"RDS", 2}
	}
	return area{service + " (not classified)", 0}
}

// Decide classifies an event and counts what is not evaluated. data says the event is an S3 data event (CloudTrail's
// eventCategory is Data); bucket is the bucket it names, checked against DataBuckets.
func (f *Filter) Decide(service, name string, data bool, bucket string) Decision {
	if data {
		ok := false
		for _, b := range f.DataBuckets {
			if b == bucket {
				ok = true
			}
		}
		if !ok {
			return f.count(Decision{Area: "S3 data events of other buckets"})
		}
	}
	a := classify(service, name, data)
	if a.wave == 0 || a.wave > f.maxWave() {
		return f.count(Decision{Wave: a.wave, Area: a.name})
	}
	return Decision{Evaluated: true, Wave: a.wave, Area: a.name}
}

func (f *Filter) count(d Decision) Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[d.Area]++
	return d
}

// Counts is how many events were not evaluated, by area.
func (f *Filter) Counts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.counts))
	for k, v := range f.counts {
		out[k] = v
	}
	return out
}

// Statement is the "not evaluated" sentence: the second-wave areas still to come (while MaxWave is 1), the
// never-evaluated list, and the counts seen so far. It is carried in the collector's health record, so a coverage
// statement reads it beside the feed's state.
func (f *Filter) Statement() string {
	var parts []string
	if f.maxWave() < 2 {
		parts = append(parts, "not yet evaluated (second release): VPC routing, Secrets Manager, Lambda configuration, EKS access, RDS")
	}
	parts = append(parts, "not evaluated: "+strings.Join(NeverEvaluated, "; "))
	c := f.Counts()
	if len(c) > 0 {
		var ks []string
		for k := range c {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var seen []string
		for _, k := range ks {
			seen = append(seen, fmt.Sprintf("%s %d", k, c[k]))
		}
		parts = append(parts, "events seen and not evaluated: "+strings.Join(seen, ", "))
	}
	return strings.Join(parts, ". ")
}

// configAreas are the Config resource types by area. A configuration item is reconciled only for an area the filter
// evaluates; the rest is counted like an event.
var configAreas = map[string]area{
	"AWS::EC2::SecurityGroup":            {"security groups", 1},
	"AWS::IAM::Role":                     {"IAM", 1},
	"AWS::IAM::Policy":                   {"IAM", 1},
	"AWS::IAM::User":                     {"IAM", 1},
	"AWS::IAM::Group":                    {"IAM", 1},
	"AWS::S3::Bucket":                    {"S3 policies and public access", 1},
	"AWS::S3::AccountPublicAccessBlock":  {"S3 policies and public access", 1},
	"AWS::KMS::Key":                      {"KMS", 1},
	"AWS::CloudTrail::Trail":             {"CloudTrail configuration", 1},
	"AWS::Config::ConfigurationRecorder": {"AWS Config configuration", 1},
	"AWS::EC2::RouteTable":               {"VPC routing", 2},
	"AWS::SecretsManager::Secret":        {"Secrets Manager", 2},
	"AWS::Lambda::Function":              {"Lambda configuration", 2},
	"AWS::EKS::Cluster":                  {"EKS access", 2},
	"AWS::RDS::DBInstance":               {"RDS", 2},
	"AWS::RDS::DBCluster":                {"RDS", 2},
}

// DecideConfig classifies a configuration item by its resource type.
func (f *Filter) DecideConfig(resourceType string) Decision {
	a, ok := configAreas[resourceType]
	if !ok {
		a = area{resourceType + " (not classified)", 0}
	}
	if a.wave == 0 || a.wave > f.maxWave() {
		return f.count(Decision{Wave: a.wave, Area: a.name})
	}
	return Decision{Evaluated: true, Wave: a.wave, Area: a.name}
}
