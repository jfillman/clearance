// Package pyyaml is PyYAML's yaml.safe_load for the values Clearance's policy diffs (AF-9a field scope, the
// GP-SCOPE cicd.yaml check): the YAML 1.1 implicit types PyYAML resolves (yes/no/on/off booleans, 0o-less octal,
// base-60 integers, `1.` floats, timestamps), merge keys, and dicts with PyYAML's key rules.
//
// Parsing is go.yaml.in/yaml/v3's; only resolution and construction are PyYAML's. Two kinds of failure:
// *Error is a yaml.YAMLError (the caller treats the file as unparseable, as the Python does), and *ValueError is
// an exception PyYAML raises that is not a YAMLError (a timestamp with day 31 in February), which the Python
// engine does not catch; the Go engine fails closed on it (R000).
package pyyaml

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/decide/pyval"
	"go.yaml.in/yaml/v3"
)

// Error is a yaml.YAMLError.
type Error struct{ Msg string }

func (e *Error) Error() string { return "yaml: " + e.Msg }

// ValueError is a non-YAML exception PyYAML raises while constructing a value.
type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return "ValueError: " + e.Msg }

// MaxNodes bounds the work one document may cause (aliases can expand a small text into a large tree). PyYAML
// has no bound; past it the Go engine denies (R000) rather than diffing.
const MaxNodes = 200_000

// SafeLoad is yaml.safe_load(text).
func SafeLoad(text string) (any, error) {
	dec := yaml.NewDecoder(strings.NewReader(text))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, &Error{Msg: err.Error()}
	}
	var next yaml.Node
	if err := dec.Decode(&next); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, &Error{Msg: err.Error()}
		}
		return nil, &Error{Msg: "expected a single document in the stream"}
	}
	c := &constructor{}
	return c.construct(&doc, 0)
}

type constructor struct{ nodes int }

func (c *constructor) construct(n *yaml.Node, depth int) (any, error) {
	c.nodes++
	if c.nodes > MaxNodes || depth > 256 {
		// Not a YAMLError: a caller that treats an unparseable file as out of scope must not let an alias bomb
		// through that way, so this fails closed (R000) instead.
		return nil, &ValueError{Msg: "document too large"}
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return c.construct(n.Content[0], depth+1)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, &Error{Msg: "found undefined alias"}
		}
		return c.construct(n.Alias, depth+1)
	case yaml.ScalarNode:
		return c.scalar(n)
	case yaml.SequenceNode:
		if n.Style&yaml.TaggedStyle != 0 && n.Tag != "!!seq" {
			return nil, unsupportedTag(n)
		}
		out := make([]any, 0, len(n.Content))
		for _, e := range n.Content {
			v, err := c.construct(e, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		if n.Style&yaml.TaggedStyle != 0 && n.Tag != "!!map" {
			return nil, unsupportedTag(n)
		}
		pairs, err := c.flatten(n, depth)
		if err != nil {
			return nil, err
		}
		m := pyval.NewMap(len(pairs) / 2)
		for i := 0; i+1 < len(pairs); i += 2 {
			k, err := c.construct(pairs[i], depth+1)
			if err != nil {
				return nil, err
			}
			v, err := c.construct(pairs[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			if !m.Set(k, v) {
				return nil, &Error{Msg: "while constructing a mapping: found unhashable key"}
			}
		}
		return m, nil
	}
	return nil, &Error{Msg: "unknown node kind"}
}

func unsupportedTag(n *yaml.Node) error {
	return &Error{Msg: fmt.Sprintf("could not determine a constructor for the tag %q", n.Tag)}
}

func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

func isMerge(k *yaml.Node) bool {
	k = deref(k)
	if k.Kind != yaml.ScalarNode {
		return false
	}
	if k.Style&yaml.TaggedStyle != 0 {
		return k.Tag == "!!merge"
	}
	return plain(k) && k.Value == "<<"
}

// flatten is PyYAML's SafeConstructor.flatten_mapping: merged pairs first (later merge sources before earlier),
// then the mapping's own, so its own keys win.
func (c *constructor) flatten(n *yaml.Node, depth int) ([]*yaml.Node, error) {
	if depth > 256 {
		return nil, &ValueError{Msg: "merge nested too deeply"}
	}
	var merge, own []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !isMerge(k) {
			own = append(own, k, v)
			continue
		}
		v = deref(v)
		switch v.Kind {
		case yaml.MappingNode:
			sub, err := c.flatten(v, depth+1)
			if err != nil {
				return nil, err
			}
			merge = append(merge, sub...)
		case yaml.SequenceNode:
			var subs [][]*yaml.Node
			for _, s := range v.Content {
				s = deref(s)
				if s.Kind != yaml.MappingNode {
					return nil, &Error{Msg: "while constructing a mapping: expected a mapping for merging"}
				}
				sub, err := c.flatten(s, depth+1)
				if err != nil {
					return nil, err
				}
				subs = append(subs, sub)
			}
			for i := len(subs) - 1; i >= 0; i-- {
				merge = append(merge, subs[i]...)
			}
		default:
			return nil, &Error{Msg: "while constructing a mapping: expected a mapping or list of mappings for merging"}
		}
	}
	return append(merge, own...), nil
}

func plain(n *yaml.Node) bool {
	return n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
}

// PyYAML's implicit resolvers (yaml/resolver.py), in the order they are tried.
var (
	reBool  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	reFloat = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	reInt   = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	reNull  = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	reTime  = regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)
	// The constructor's own regexp, with groups.
	reTimeParts = regexp.MustCompile(`^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.([0-9]*))?(?:[ \t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?)?$`)
)

func resolve(v string) string {
	first := byte(0)
	if v != "" {
		first = v[0]
	}
	switch {
	case strings.IndexByte("yYnNtTfFoO", first) >= 0 && first != 0 && reBool.MatchString(v):
		return "!!bool"
	}
	if first != 0 && strings.IndexByte("-+0123456789.", first) >= 0 && reFloat.MatchString(v) {
		return "!!float"
	}
	if first != 0 && strings.IndexByte("-+0123456789", first) >= 0 && reInt.MatchString(v) {
		return "!!int"
	}
	if first == '<' && v == "<<" {
		return "!!merge"
	}
	if (first == 0 || strings.IndexByte("~nN", first) >= 0) && reNull.MatchString(v) {
		return "!!null"
	}
	if first >= '0' && first <= '9' && reTime.MatchString(v) {
		return "!!timestamp"
	}
	if v == "=" {
		return "!!value"
	}
	return "!!str"
}

func (c *constructor) scalar(n *yaml.Node) (any, error) {
	tag := "!!str"
	switch {
	case n.Style&yaml.TaggedStyle != 0:
		tag = n.Tag
	case plain(n):
		tag = resolve(n.Value)
	}
	v := n.Value
	switch tag {
	case "!!str":
		return v, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		switch strings.ToLower(v) {
		case "yes", "true", "on":
			return true, nil
		case "no", "false", "off":
			return false, nil
		}
		return nil, &Error{Msg: fmt.Sprintf("bad bool %q", v)} // KeyError in PyYAML; not reachable for an implicit bool
	case "!!int":
		return constructInt(v)
	case "!!float":
		return constructFloat(v)
	case "!!timestamp":
		return constructTimestamp(v)
	case "!!merge":
		return v, nil
	}
	return nil, unsupportedTag(n)
}

func constructInt(raw string) (any, error) {
	v := strings.ReplaceAll(raw, "_", "")
	sign := int64(1)
	if v != "" && v[0] == '-' {
		sign = -1
	}
	if v != "" && (v[0] == '-' || v[0] == '+') {
		v = v[1:]
	}
	b := new(big.Int)
	ok := true
	switch {
	case v == "0":
		return int64(0), nil
	case strings.HasPrefix(v, "0b"):
		_, ok = b.SetString(v[2:], 2)
	case strings.HasPrefix(v, "0x"):
		_, ok = b.SetString(v[2:], 16)
	case v != "" && v[0] == '0':
		_, ok = b.SetString(v, 8)
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		base := big.NewInt(1)
		for i := len(parts) - 1; i >= 0; i-- {
			d, good := new(big.Int).SetString(parts[i], 10)
			if !good {
				ok = false
				break
			}
			b.Add(b, d.Mul(d, base))
			base = new(big.Int).Mul(base, big.NewInt(60))
		}
	default:
		_, ok = b.SetString(v, 10)
	}
	if !ok {
		return nil, &ValueError{Msg: fmt.Sprintf("invalid literal for int(): %q", raw)}
	}
	if sign < 0 {
		b.Neg(b)
	}
	if b.IsInt64() {
		return b.Int64(), nil
	}
	return b, nil
}

func constructFloat(raw string) (any, error) {
	v := strings.ToLower(strings.ReplaceAll(raw, "_", ""))
	sign := 1.0
	if v != "" && v[0] == '-' {
		sign = -1
	}
	if v != "" && (v[0] == '-' || v[0] == '+') {
		v = v[1:]
	}
	switch {
	case v == ".inf":
		return sign * math.Inf(1), nil
	case v == ".nan":
		return math.NaN(), nil
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		total, base := 0.0, 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			f, err := strconv.ParseFloat(parts[i], 64)
			if err != nil {
				return nil, &ValueError{Msg: fmt.Sprintf("could not convert string to float: %q", raw)}
			}
			total += f * base
			base *= 60
		}
		return sign * total, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, &ValueError{Msg: fmt.Sprintf("could not convert string to float: %q", raw)}
	}
	return sign * f, nil
}

func constructTimestamp(v string) (any, error) {
	m := reTimeParts.FindStringSubmatch(v)
	if m == nil {
		return nil, &ValueError{Msg: "bad timestamp " + strconv.Quote(v)}
	}
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	y, mo, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
	if !validDate(y, mo, d) {
		return nil, &ValueError{Msg: "day is out of range for month"}
	}
	if m[4] == "" {
		return pyval.Date{Y: y, M: mo, D: d}, nil
	}
	t := pyval.DateTime{Y: y, M: mo, D: d, H: atoi(m[4]), Min: atoi(m[5]), S: atoi(m[6])}
	if t.H > 23 || t.Min > 59 || t.S > 59 {
		return nil, &ValueError{Msg: "time component out of range"}
	}
	if frac := m[7]; frac != "" {
		frac = (frac + "000000")[:6]
		t.Micro = atoi(frac)
	}
	switch {
	case m[8] == "Z":
		t.Aware = true
	case m[9] != "":
		off := atoi(m[10])*3600 + atoi(m[11])*60
		if m[9] == "-" {
			off = -off
		}
		if off <= -86400 || off >= 86400 {
			return nil, &ValueError{Msg: "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24)"}
		}
		t.Aware, t.Offset = true, off
	}
	return t, nil
}

func validDate(y, m, d int) bool {
	if y < 1 || m < 1 || m > 12 || d < 1 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[m-1]
	if m == 2 && (y%4 == 0 && (y%100 != 0 || y%400 == 0)) {
		days = 29
	}
	return d <= days
}
