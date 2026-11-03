package profile

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/jfillman/clearance/internal/pycompat"
)

// explain picks one error the way python-jsonschema's best_match does (the shallowest error, a non-oneOf/anyOf
// one first; inside a oneOf/anyOf the deepest, unless two tie) and words it as python-jsonschema would. The
// wording follows jsonschema 4.26 for the keywords this schema uses; the choice among several errors is a close
// approximation, not a byte-for-byte port.
func explain(err error, doc any) (path, msg string) {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return "<root>", err.Error()
	}
	best := pick(flatten(ve), false)
	if best == nil {
		return "<root>", ve.Error()
	}
	for weak(best) {
		ctx := flatten(&jsonschema.ValidationError{Causes: best.Causes})
		next := pick(ctx, true)
		if next == nil {
			break
		}
		best = next
	}
	path = strings.Join(best.InstanceLocation, "/")
	if path == "" {
		path = "<root>"
	}
	return path, word(best, at(doc, best.InstanceLocation))
}

func weak(e *jsonschema.ValidationError) bool {
	switch e.ErrorKind.(type) {
	case *kind.OneOf, *kind.AnyOf:
		return true
	}
	return false
}

// flatten is the errors python-jsonschema's iter_errors yields: wrappers (a schema, a group, allOf, a $ref)
// dissolved into their causes; oneOf and anyOf kept whole, their branches as context.
func flatten(e *jsonschema.ValidationError) []*jsonschema.ValidationError {
	var out []*jsonschema.ValidationError
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		switch e.ErrorKind.(type) {
		case nil, *kind.Schema, *kind.Group, *kind.AllOf, *kind.Reference:
			for _, c := range e.Causes {
				walk(c)
			}
		default:
			out = append(out, e)
		}
	}
	walk(e)
	return out
}

func less(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			continue
		}
		ai, e1 := strconv.Atoi(a[i])
		bi, e2 := strconv.Atoi(b[i])
		if e1 == nil && e2 == nil {
			if ai < bi {
				return -1
			}
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
		return 1
	}
	return len(a) - len(b)
}

// pick is the most relevant error: the shallowest (deepest when inContext), then the earliest path, then not
// weak. In a context, a tie between the two best means none is picked (best_match keeps the oneOf itself).
func pick(errs []*jsonschema.ValidationError, inContext bool) *jsonschema.ValidationError {
	better := func(a, b *jsonschema.ValidationError) int { // <0: a is more relevant
		la, lb := len(a.InstanceLocation), len(b.InstanceLocation)
		if la != lb {
			if (la < lb) != inContext {
				return -1
			}
			return 1
		}
		if c := less(a.InstanceLocation, b.InstanceLocation); c != 0 {
			return c
		}
		if weak(a) != weak(b) {
			if weak(b) {
				return -1
			}
			return 1
		}
		return 0
	}
	var best, second *jsonschema.ValidationError
	for _, e := range errs {
		switch {
		case best == nil || better(e, best) < 0:
			best, second = e, best
		case second == nil || better(e, second) < 0:
			second = e
		}
	}
	if inContext && best != nil && second != nil && better(best, second) == 0 {
		return nil
	}
	return best
}

// at is the instance value at loc.
func at(doc any, loc []string) any {
	v := doc
	for _, p := range loc {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(x) {
				return nil
			}
			v = x[i]
		default:
			return nil
		}
	}
	return v
}

func rat(r *big.Rat) string {
	if r.IsInt() {
		return r.Num().String()
	}
	f, _ := r.Float64()
	return pycompat.FloatRepr(f)
}

func quoted(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = pycompat.Repr(x)
	}
	return strings.Join(q, ", ")
}

// word is python-jsonschema's message for e, whose instance is v.
func word(e *jsonschema.ValidationError, v any) string {
	r := pycompat.Repr(v)
	switch k := e.ErrorKind.(type) {
	case *kind.Required:
		return pycompat.Repr(k.Missing[0]) + " is a required property"
	case *kind.AdditionalProperties:
		verb := "was"
		if len(k.Properties) > 1 {
			verb = "were"
		}
		return fmt.Sprintf("Additional properties are not allowed (%s %s unexpected)", quoted(k.Properties), verb)
	case *kind.Type:
		if len(k.Want) == 1 {
			return fmt.Sprintf("%s is not of type %s", r, pycompat.Repr(k.Want[0]))
		}
		return fmt.Sprintf("%s is not of type %s", r, quoted(k.Want))
	case *kind.Enum:
		return fmt.Sprintf("%s is not one of %s", r, pycompat.Repr(k.Want))
	case *kind.Const:
		return pycompat.Repr(k.Want) + " was expected"
	case *kind.Pattern:
		return fmt.Sprintf("%s does not match %s", r, pycompat.Repr(k.Want))
	case *kind.Minimum:
		return fmt.Sprintf("%s is less than the minimum of %s", r, rat(k.Want))
	case *kind.Maximum:
		return fmt.Sprintf("%s is greater than the maximum of %s", r, rat(k.Want))
	case *kind.MinLength:
		if k.Want == 1 {
			return r + " should be non-empty"
		}
		return r + " is too short"
	case *kind.MaxLength, *kind.MaxItems:
		return r + " is too long"
	case *kind.MinItems:
		if k.Want == 1 {
			return r + " should be non-empty"
		}
		return r + " is too short"
	case *kind.MinProperties:
		if k.Want == 1 {
			return r + " should be non-empty"
		}
		return r + " does not have enough properties"
	case *kind.UniqueItems:
		return r + " has non-unique elements"
	case *kind.PropertyNames:
		return fmt.Sprintf("%s does not match the property names schema", pycompat.Repr(k.Property))
	case *kind.OneOf:
		if len(k.Subschemas) > 1 {
			return r + " is valid under each of the given schemas"
		}
		return r + " is not valid under any of the given schemas"
	case *kind.AnyOf:
		return r + " is not valid under any of the given schemas"
	}
	return e.Error()
}
