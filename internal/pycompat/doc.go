// Package pycompat reproduces the Python behaviours Clearance's decisions, records, digests and messages depend on
// byte for byte. It is the one home for them in the Go core: the decision engine, the gate, review, definitions,
// provenance, the GitHub App and the server all use it.
//
// Two value models are accepted, and every function here takes either:
//
//   - the JSON model, what encoding/json (UseNumber) or canon.Parse produces: nil, bool, string, json.Number,
//     float64, []any, map[string]any (int, int64, *big.Int and []string are accepted too). A map[string]any keeps
//     no key order, so Repr and Dumps write its keys sorted.
//   - the dict model, what DecodeJSON and pyyaml.SafeLoad produce, where Python's own types matter (dict order,
//     non-string keys, datetimes): nil, bool, int64, *big.Int (an integer outside int64, held exactly), float64,
//     string, []any, *Map (an insertion-ordered dict), Date and DateTime (PyYAML timestamps).
//
// Equality follows Python's: True == 1 == 1.0, an int and a float compare exactly, a dict equals another with the
// same keys whatever their order, and NaN equals NaN only inside a container (EqualIn), where Python compares
// PyYAML's one shared NaN object by identity.
//
// What lives here: json.dumps and its variants (Dumps, DumpsLen, ASCIIEscape), json.loads (Decode, DecodeJSON),
// repr()/str() (Repr, Str, StrRepr, FloatRepr), str methods (Lower, Strip, IsSpace, Printable, Len, Truncate),
// truth and equality (Truthy, Equal, EqualIn, NumCmp, Number, IsInt, AsInt, TypeName), fnmatch.fnmatchcase
// (Match, MatchAny, FnmatchTranslate) and datetime.isoformat (ISO, Isoformat, ParseIsoformat).
//
// The evidence chain's canonical JSON is internal/canon (the lower layer, which this package uses for float digits,
// parsing and digests); YAML 1.1 loading is internal/pyyaml; scope.py's path globs are internal/scope.
//
// Python reference values: testdata/vectors.json, written by tools/golden/gen_vectors.py.
package pycompat
