package render

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jfillman/clearance/internal/pycompat"
)

// The documents of a rendered manifest file, read the way register.py reads them: yaml.safe_load_all, PyYAML's
// YAML 1.1 SafeLoader. yaml.v3 parses; this file resolves plain scalars with PyYAML's implicit resolvers (so
// `yes` is True, `1e3` a string, `0755` octal, `1:30` sexagesimal, a timestamp a date) and applies `<<` merges,
// keeping each mapping's key order for the walks where it shows (images).

// omap is a mapping in insertion order.
type omap struct {
	keys []string
	vals map[string]any
}

var (
	boolRx  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	floatRx = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	intRx   = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	nullRx  = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	tsRx    = regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)
	tsParts = regexp.MustCompile(`^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.([0-9]*))?(?:[ \t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?)?$`)
)

// loadAll is yaml.safe_load_all: every document of the stream, ordered.
func loadAll(data []byte) ([]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []any
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if len(n.Content) == 0 {
			out = append(out, nil)
			continue
		}
		b := &builder{budget: maxNodes}
		v, err := b.construct(n.Content[0], 0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

const (
	maxDepth = 512
	// maxNodes bounds what one document may expand to through aliases (a "billion laughs" document).
	maxNodes = 1 << 20
)

type builder struct{ budget int }

func (b *builder) construct(n *yaml.Node, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("yaml: nesting too deep")
	}
	if b.budget--; b.budget < 0 {
		return nil, errors.New("yaml: the document expands to too many nodes")
	}
	switch n.Kind {
	case yaml.AliasNode:
		return b.construct(n.Alias, depth+1)
	case yaml.ScalarNode:
		return scalar(n)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := b.construct(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		pairs, err := b.flatten(n, depth)
		if err != nil {
			return nil, err
		}
		m := &omap{vals: map[string]any{}}
		for i := 0; i+1 < len(pairs); i += 2 {
			kv, err := b.construct(pairs[i], depth+1)
			if err != nil {
				return nil, err
			}
			k := keyString(kv)
			v, err := b.construct(pairs[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			if _, seen := m.vals[k]; !seen {
				m.keys = append(m.keys, k)
			}
			m.vals[k] = v
		}
		return m, nil
	}
	return nil, fmt.Errorf("yaml: unexpected node kind %d", n.Kind)
}

func isMerge(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && (k.Tag == "!!merge" || (k.Value == "<<" && k.Style == 0 && k.Tag != "!!str"))
}

// flatten is PyYAML's flatten_mapping: `<<` values (a mapping, or a list of them, the last first) come before the
// mapping's own keys, so its own keys win.
func (b *builder) flatten(n *yaml.Node, depth int) ([]*yaml.Node, error) {
	if b.budget--; depth > maxDepth || b.budget < 0 {
		return nil, errors.New("yaml: nesting too deep")
	}
	var merge, own []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !isMerge(k) {
			own = append(own, k, v)
			continue
		}
		for v.Kind == yaml.AliasNode {
			v = v.Alias
		}
		switch v.Kind {
		case yaml.MappingNode:
			sub, err := b.flatten(v, depth+1)
			if err != nil {
				return nil, err
			}
			merge = append(merge, sub...)
		case yaml.SequenceNode:
			var subs [][]*yaml.Node
			for _, s := range v.Content {
				for s.Kind == yaml.AliasNode {
					s = s.Alias
				}
				if s.Kind != yaml.MappingNode {
					return nil, errors.New("yaml: a merge list holds mappings only")
				}
				sub, err := b.flatten(s, depth+1)
				if err != nil {
					return nil, err
				}
				subs = append(subs, sub)
			}
			for i := len(subs) - 1; i >= 0; i-- {
				merge = append(merge, subs[i]...)
			}
		default:
			return nil, errors.New("yaml: a merge takes a mapping or a list of mappings")
		}
	}
	return append(merge, own...), nil
}

// keyString is a mapping key as json.dumps writes it: a string itself, else its JSON form (1, true, null).
func keyString(k any) string {
	switch x := k.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	}
	b, err := pycompat.Dumps(k, pycompat.Options{})
	if err != nil {
		return pycompat.Str(k)
	}
	return string(b)
}

func scalar(n *yaml.Node) (any, error) {
	tag := ""
	if n.Style&yaml.TaggedStyle != 0 {
		tag = n.Tag
	}
	plain := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
	v := n.Value
	if tag == "" {
		if !plain {
			return v, nil
		}
		switch {
		case boolRx.MatchString(v):
			tag = "!!bool"
		case intRx.MatchString(v):
			tag = "!!int"
		case floatRx.MatchString(v):
			tag = "!!float"
		case nullRx.MatchString(v):
			tag = "!!null"
		case tsRx.MatchString(v):
			tag = "!!timestamp"
		case v == "=":
			// PyYAML resolves a plain "=" to tag:yaml.org,2002:value, which SafeLoader cannot construct.
			return nil, errors.New("yaml: could not determine a constructor for the tag 'tag:yaml.org,2002:value'")
		default:
			return v, nil
		}
	}
	switch tag {
	case "!!str", "!":
		return v, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		switch strings.ToLower(v) {
		case "yes", "true", "on":
			return true, nil
		}
		return false, nil
	case "!!int":
		return yamlInt(v)
	case "!!float":
		return yamlFloat(v)
	case "!!timestamp":
		return timestamp(v)
	}
	return nil, fmt.Errorf("yaml: could not determine a constructor for the tag %s", tag)
}

func yamlInt(s string) (any, error) {
	v := strings.ReplaceAll(s, "_", "")
	sign := 1
	if strings.HasPrefix(v, "-") {
		sign, v = -1, v[1:]
	} else if strings.HasPrefix(v, "+") {
		v = v[1:]
	}
	z := new(big.Int)
	ok := true
	switch {
	case v == "0":
	case strings.HasPrefix(v, "0b"):
		_, ok = z.SetString(v[2:], 2)
	case strings.HasPrefix(v, "0x"):
		_, ok = z.SetString(v[2:], 16)
	case strings.HasPrefix(v, "0"):
		_, ok = z.SetString(v, 8)
	case strings.Contains(v, ":"):
		base := big.NewInt(1)
		parts := strings.Split(v, ":")
		for i := len(parts) - 1; i >= 0; i-- {
			d, err := strconv.ParseInt(parts[i], 10, 64)
			if err != nil {
				return nil, err
			}
			z.Add(z, new(big.Int).Mul(big.NewInt(d), base))
			base.Mul(base, big.NewInt(60))
		}
	default:
		_, ok = z.SetString(v, 10)
	}
	if !ok {
		return nil, fmt.Errorf("yaml: bad int %q", s)
	}
	if sign < 0 {
		z.Neg(z)
	}
	if z.IsInt64() {
		return z.Int64(), nil
	}
	return z, nil
}

func yamlFloat(s string) (any, error) {
	v := strings.ToLower(strings.ReplaceAll(s, "_", ""))
	sign := 1.0
	if strings.HasPrefix(v, "-") {
		sign, v = -1, v[1:]
	} else if strings.HasPrefix(v, "+") {
		v = v[1:]
	}
	switch {
	case v == ".inf":
		return sign * math.Inf(1), nil
	case v == ".nan":
		return math.NaN(), nil
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		base, total := 1.0, 0.0
		for i := len(parts) - 1; i >= 0; i-- {
			d, err := strconv.ParseFloat(parts[i], 64)
			if err != nil {
				return nil, err
			}
			total += d * base
			base *= 60
		}
		return sign * total, nil
	}
	if strings.HasSuffix(v, ".") {
		v += "0"
	}
	if strings.HasPrefix(v, ".") {
		v = "0" + v
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		var ne *strconv.NumError
		if !errors.As(err, &ne) || ne.Err != strconv.ErrRange {
			return nil, err
		}
	}
	return sign * f, nil
}

// timestamp is PyYAML's date or datetime, as str() (default=str) prints it.
func timestamp(s string) (any, error) {
	m := tsParts.FindStringSubmatch(s)
	if m == nil {
		return s, nil
	}
	y, _ := strconv.Atoi(m[1])
	mo, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[3])
	if m[4] == "" {
		return fmt.Sprintf("%04d-%02d-%02d", y, mo, d), nil
	}
	h, _ := strconv.Atoi(m[4])
	mi, _ := strconv.Atoi(m[5])
	sec, _ := strconv.Atoi(m[6])
	out := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", y, mo, d, h, mi, sec)
	if frac := m[7]; frac != "" {
		if len(frac) > 6 {
			frac = frac[:6]
		}
		frac += strings.Repeat("0", 6-len(frac))
		if us, _ := strconv.Atoi(frac); us != 0 {
			out += "." + frac
		}
	}
	switch {
	case m[8] == "Z":
		out += "+00:00"
	case m[9] != "":
		th, _ := strconv.Atoi(m[10])
		tm := 0
		if m[11] != "" {
			tm, _ = strconv.Atoi(m[11])
		}
		out += fmt.Sprintf("%s%02d:%02d", m[9], th, tm)
	}
	return out, nil
}

// plain is the value with every omap turned into a map[string]any.
func plain(v any) any {
	switch x := v.(type) {
	case *omap:
		m := make(map[string]any, len(x.keys))
		for _, k := range x.keys {
			m[k] = plain(x.vals[k])
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plain(e)
		}
		return out
	}
	return v
}
