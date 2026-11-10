package collector

import (
	"encoding/json"
	"sort"
	"strings"
)

// The diff of a change Config did not describe. A console change shows up in AWS Config minutes after CloudTrail, and
// a CREATE configuration item lists no changed properties at all; the CloudTrail event's own request says what was
// asked for, so when no Config diff is available it is the observation's state_change:
//
//	{before: {}, after: <the request, secrets stripped and bounded>, source: "cloudtrail-request"}
//
// This is the request, not a verified result of the change: source says so.
const sourceRequest = "cloudtrail-request"

// redacted replaces the value of a secret-bearing parameter. The key stays: that the call carried a password is part of
// what was done.
const redacted = "[redacted]"

// secretKeys are request or response parameter names that carry a credential or key material, compared lower-cased
// and without separators. A name containing any of secretParts is treated the same way. This is the AWS counterpart of
// the Kubernetes Secret guard (an observation never carries a secret's body): Secrets Manager is second-wave and not
// evaluated, but its parameters are on the list so that the day it is evaluated nothing has to be remembered.
var secretKeys = map[string]bool{
	"password": true, "masteruserpassword": true, "adminpassword": true, "newpassword": true, "oldpassword": true,
	"secretstring": true, "secretbinary": true, "secretaccesskey": true, "sessiontoken": true, "securitytoken": true,
	"userdata": true, "privatekey": true, "keymaterial": true, "keymaterialwithprivate": true, "plaintext": true,
	"ciphertextblob": true, "ciphertext": true, "importedkeymaterial": true, "clientsecret": true, "authtoken": true,
	"authorizationtoken": true, "apikey": true, "credentials": true, "connectionpassword": true, "kmsdatakey": true,
	"certificatechain": true, "pfx": true, "token": true, "accesstoken": true, "refreshtoken": true, "idtoken": true,
	"environment": true, "variables": true, // Lambda environment variables
}

var secretParts = []string{"password", "secret", "privatekey", "passphrase", "credential", "token"}

func secretKey(k string) bool {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k))
	if secretKeys[n] {
		return true
	}
	for _, p := range secretParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// stripSecrets copies v with the value of every secret-bearing key replaced. Depth-limited like the rest.
func stripSecrets(v any, depth int) any {
	if depth > 8 {
		return redacted
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if secretKey(k) {
				out[k] = redacted
				continue
			}
			out[k] = stripSecrets(e, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = stripSecrets(e, depth+1)
		}
		return out
	}
	return v
}

// requestDiff is the state_change an event carries when no Config diff joined it; nil when the request has nothing
// (a call with no parameters).
func requestDiff(v *ctView) map[string]any {
	if len(v.Request) == 0 {
		return nil
	}
	after := stripSecrets(v.Request, 0).(map[string]any)
	if b, _ := json.Marshal(after); len(b) > maxStateChange {
		keys := make([]string, 0, len(after))
		for k := range after {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		after = map[string]any{"truncated": "the request is larger than the diff limit; its parameter names are kept", "parameters": keys}
	}
	return map[string]any{"before": map[string]any{}, "after": after, "source": sourceRequest}
}

// idKeys are the response elements that name the resource a call created, in the order they are preferred.
var idKeys = []string{"groupId", "instanceId", "vpcId", "subnetId", "snapshotId", "volumeId", "networkInterfaceId",
	"imageId", "allocationId", "routeTableId", "internetGatewayId", "natGatewayId", "transitGatewayId", "keyId"}

// createCall says the API makes a resource: only then does its response name one as created.
func createCall(name string) bool {
	for _, p := range []string{"Create", "Run", "Allocate", "Import", "Register", "Copy"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// createdID is the id the response gives the created resource (an ec2 CreateSecurityGroup answers groupId sg-...), or
// "" when it names none.
func createdID(v *ctView) string {
	if !createCall(v.Name) { // AttachVolume answers instanceId and volumeId: both existing resources
		return ""
	}
	for _, k := range idKeys {
		if s := str(v.Response[k]); s != "" && len(s) <= 256 && !strings.ContainsAny(s, " \t\n") {
			return s
		}
	}
	return ""
}
