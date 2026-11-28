package schemas

import "strconv"

// The product names the public contract bakes in, and that change when the owner decides Clearance's own product
// domain (Y-55; N-7 renames the API group and predicate domain). Both values here are PLACEHOLDERS until then. The
// switch is an edit to this file, then `go test ./schemas -update` (it rewrites the SDK-1 schemas' $id) and
// `go generate ./internal/server` (the contract's x-clearance-published-schemas).

// SchemaBase is the base URL of the schemas SDK-1 publishes (schemas/change-description.schema.json,
// schemas/kind.schema.json): a schema's $id is SchemaBase + name + "/v" + version + ".json". PLACEHOLDER: the current
// Hangar-named host, kept until the product domain is decided. The schemas published before SDK-1 keep their own
// $id until N-7.
const SchemaBase = "https://clearance.hangarplatform.dev/schemas/"

// FirstPartyPrefix is the reverse-DNS prefix reserved for first-party subject kinds: the reversed product domain.
// PLACEHOLDER (dev.clearance.*) until the product domain is decided.
const FirstPartyPrefix = "dev.clearance."

// SchemaID is the $id of a published schema.
func SchemaID(name string, version int) string {
	return SchemaBase + name + "/v" + strconv.Itoa(version) + ".json"
}
