package collector

import (
	"encoding/json"
	"fmt"
	"time"
)

// Documentation-style identifiers: account 111122223333, the SSO admin and apply roles of the default rule bundle.
const (
	acct      = "111122223333"
	applyRole = "arn:aws:iam::111122223333:role/clearance-apply"
	ssoRole   = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

type ct struct {
	id, name, source string
	at               time.Time
	issuer, arn      string
	utype            string
	srcIdentity      string
	userAgent        string
	errCode          string
	params           map[string]any
	category         string
	readOnly         *bool
}

// consoleSG is a console security-group change by the SSO admin role.
func consoleSG(id string, at time.Time) ct {
	return ct{id: id, name: "AuthorizeSecurityGroupIngress", source: "ec2.amazonaws.com", at: at, utype: "AssumedRole",
		issuer: ssoRole, arn: "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123456789abcdef/dana", srcIdentity: "dana@example.com",
		userAgent: "console.ec2.amazonaws.com", params: map[string]any{"groupId": "sg-0abc1234"}}
}

// gatedSG is the same call made by the apply role under a grant's plan digest.
func gatedSG(id string, at time.Time) ct {
	c := consoleSG(id, at)
	c.issuer = applyRole
	c.arn = "arn:aws:sts::111122223333:assumed-role/clearance-apply/tf-run-77"
	c.srcIdentity = "run=77"
	c.userAgent = "APN/1.0 HashiCorp/1.0 Terraform/1.13.4 clearance/grant=clr_apply1;plan=sha256:" + planDigest
	return c
}

const planDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func (c ct) json() json.RawMessage {
	ui := map[string]any{"type": c.utype, "arn": c.arn, "accountId": acct}
	if c.issuer != "" {
		sc := map[string]any{"sessionIssuer": map[string]any{"arn": c.issuer, "type": "Role"}}
		if c.srcIdentity != "" {
			sc["sourceIdentity"] = c.srcIdentity
		}
		ui["sessionContext"] = sc
	}
	m := map[string]any{"eventVersion": "1.10", "eventID": c.id, "eventName": c.name, "eventSource": c.source,
		"eventTime": c.at.UTC().Format(time.RFC3339), "awsRegion": "us-east-1", "recipientAccountId": acct,
		"userIdentity": ui, "userAgent": c.userAgent, "requestParameters": c.params}
	if c.errCode != "" {
		m["errorCode"] = c.errCode
		m["errorMessage"] = "not authorized"
	}
	if c.category != "" {
		m["eventCategory"] = c.category
	}
	if c.readOnly != nil {
		m["readOnly"] = *c.readOnly
	}
	b, _ := json.Marshal(m)
	return b
}

// envelopeOf wraps a CloudTrail record the way EventBridge delivers it to the queue.
func (c ct) envelope() []byte {
	b, _ := json.Marshal(map[string]any{"version": "0", "id": "eb-" + c.id, "detail-type": "AWS API Call via CloudTrail",
		"source": "aws.ec2", "account": acct, "time": c.at.UTC().Format(time.RFC3339), "region": "us-east-1", "detail": c.json()})
	return b
}

type cfgItem struct {
	resourceID, name string
	at               time.Time
	related          []string
	changed          map[string]map[string]any
}

func sgConfig(at time.Time, related ...string) cfgItem {
	return cfgItem{resourceID: "sg-0abc1234", name: "web", at: at, related: related, changed: map[string]map[string]any{
		"Configuration.IpPermissions.0": {"previousValue": nil, "updatedValue": map[string]any{"fromPort": 22, "toPort": 22, "ipRanges": []string{"0.0.0.0/0"}}, "changeType": "CREATE"}}}
}

func (c cfgItem) envelope() []byte {
	item := map[string]any{"configurationItemStatus": "OK", "configurationItemCaptureTime": c.at.UTC().Format(time.RFC3339),
		"resourceType": "AWS::EC2::SecurityGroup", "resourceId": c.resourceID, "resourceName": c.name,
		"ARN": fmt.Sprintf("arn:aws:ec2:us-east-1:%s:security-group/%s", acct, c.resourceID), "awsRegion": "us-east-1", "awsAccountId": acct}
	if len(c.related) > 0 {
		item["relatedEvents"] = c.related
	}
	b, _ := json.Marshal(map[string]any{"version": "0", "id": "cfg-" + c.at.Format("150405"), "detail-type": "Config Configuration Item Change",
		"source": "aws.config", "account": acct, "region": "us-east-1", "time": c.at.UTC().Format(time.RFC3339),
		"detail": map[string]any{"messageType": "ConfigurationItemChangeNotification",
			"configurationItemDiff": map[string]any{"changeType": "UPDATE", "changedProperties": c.changed}, "configurationItem": item}})
	return b
}

func mustItem(body []byte, at time.Time) *Item {
	it, err := ParseMessage(body, at)
	if err != nil {
		panic(err)
	}
	return it
}
