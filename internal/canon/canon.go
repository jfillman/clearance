// Package canon is the evidence chain's canonical JSON, byte for byte the Python core's
//
//	json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
//
// (clearance audit.py canonical), so the Go core verifies and extends the chain the Python core wrote.
//
// Values are what Parse (or encoding/json with UseNumber) produces: nil, bool, string, json.Number, []any and
// map[string]any; float64, float32, the integer types, json.RawMessage, and slices and string-keyed maps of
// supported values are accepted too. A json.Number is an integer or a float by its literal, the way Python's
// json.loads decides: a literal with '.', 'e' or 'E' is a float and is printed with Python's float repr
// (1.0, 1e-05, 1e+16, -0.0); any other literal is a Python int and is printed as its digits ("-0" prints "0").
//
// Where Python and Go's encoding/json differ, Python wins:
//   - keys sort by code point (for valid UTF-8 that is byte order; lone surrogates are an error, as they are in
//     Python's .encode());
//   - only '"', '\\' and control characters below U+0020 are escaped (\n \r \t \b \f short, the rest \u00XX);
//     '<', '>', '&', U+2028, U+2029 and DEL are written raw (encoding/json escapes the first five);
//   - floats are Python's repr, not encoding/json's 'g'-like format (1e+21 vs 1e21, 1.0 vs 1);
//   - NaN and ±Inf (a float64 value, or a float literal that overflows, such as 1e400) are written as Python
//     writes them: NaN, Infinity, -Infinity. Parse rejects those tokens in input: they are not JSON, and Postgres
//     jsonb, where the chain lives, refuses them.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxIntDigits is Python's default int max str digits (sys.get_int_max_str_digits): json.loads refuses a longer
// integer literal, so Canonical and Parse do too.
const MaxIntDigits = 4300

// MaxDepth bounds nesting in Parse and Canonical (Python's json recursion fails near its recursion limit, 1000).
const MaxDepth = 512

// ErrUnsupported is returned for a Go value with no JSON form here.
var ErrUnsupported = errors.New("canon: unsupported value")

// Canonical returns v's canonical JSON.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// SHA256Hex is the lowercase hex SHA-256 of b (audit.py sha256_hex).
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ArgsDigest is the hash of a call's arguments as records carry it (audit.py args_digest).
func ArgsDigest(args any) (string, error) {
	c, err := Canonical(args)
	if err != nil {
		return "", err
	}
	return SHA256Hex(c), nil
}

// IsFloatLiteral reports whether a JSON number literal is a float to Python's json.loads.
func IsFloatLiteral(lit string) bool { return strings.ContainsAny(lit, ".eE") }

func write(b *bytes.Buffer, v any, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("canon: nesting deeper than %d", MaxDepth)
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return writeString(b, x)
	case json.Number:
		return writeNumber(b, string(x))
	case float64:
		b.WriteString(PyFloat(x))
	case float32:
		b.WriteString(PyFloat(float64(x)))
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int8:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint8:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint16:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case json.RawMessage:
		p, err := Parse(x)
		if err != nil {
			return err
		}
		return write(b, p, depth)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		return writeObject(b, keys, func(k string) any { return x[k] }, depth)
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		return writeReflect(b, v, depth)
	}
	return nil
}

func writeReflect(b *bytes.Buffer, v any, depth int) error {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, rv.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("%w: map key type %s", ErrUnsupported, rv.Type().Key())
		}
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		keys := make([]string, 0, rv.Len())
		for _, k := range rv.MapKeys() {
			keys = append(keys, k.String())
		}
		return writeObject(b, keys, func(k string) any {
			return rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key())).Interface()
		}, depth)
	case reflect.Pointer:
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		return write(b, rv.Elem().Interface(), depth+1)
	}
	return fmt.Errorf("%w: %T", ErrUnsupported, v)
}

func writeObject(b *bytes.Buffer, keys []string, get func(string) any, depth int) error {
	// Python sorts str keys by code point. For valid UTF-8 (checked in writeString) byte order is code point
	// order, so a byte sort is exact; UTF-16 order (U+FFFF after U+10000) is what this must not do.
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeString(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := write(b, get(k), depth+1); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

const hexDigits = "0123456789abcdef"

func writeString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canon: string is not valid UTF-8")
	}
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b.WriteString(s[start:i])
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		}
		start = i + 1
	}
	b.WriteString(s[start:])
	b.WriteByte('"')
	return nil
}

func writeNumber(b *bytes.Buffer, lit string) error {
	if !validNumber(lit) {
		return fmt.Errorf("canon: %q is not a JSON number", lit)
	}
	if IsFloatLiteral(lit) {
		f, err := strconv.ParseFloat(lit, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return fmt.Errorf("canon: %w", err)
		}
		// Overflow gives ±Inf, underflow ±0, exactly as Python's float() does.
		b.WriteString(PyFloat(f))
		return nil
	}
	digits := strings.TrimPrefix(lit, "-")
	if len(digits) > MaxIntDigits {
		return fmt.Errorf("canon: integer literal of %d digits exceeds Python's limit of %d", len(digits), MaxIntDigits)
	}
	if digits == "0" {
		b.WriteString("0") // Python: int("-0") == 0
		return nil
	}
	b.WriteString(lit)
	return nil
}

// validNumber is the JSON number grammar: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?
func validNumber(s string) bool {
	n, ok := scanNumber(s, 0)
	return ok && n == len(s)
}

// scanNumber returns the end of the number literal starting at s[i].
func scanNumber[T string | []byte](s T, i int) (int, bool) {
	if i < len(s) && s[i] == '-' {
		i++
	}
	switch {
	case i < len(s) && s[i] == '0':
		i++
	case i < len(s) && s[i] >= '1' && s[i] <= '9':
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	default:
		return i, false
	}
	if i < len(s) && s[i] == '.' {
		i++
		st := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == st {
			return i, false
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		st := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == st {
			return i, false
		}
	}
	return i, true
}

// PyFloat is Python's repr(float): the shortest round-tripping digits, fixed notation when the decimal exponent
// is in (-4, 16], scientific otherwise, always with a '.0' or an exponent so it reads back as a float.
func PyFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // [-]d[.ddd]e±XX
	neg := s[0] == '-'
	if neg {
		s = s[1:]
	}
	ei := strings.IndexByte(s, 'e')
	mant, exps := s[:ei], s[ei+1:]
	exp, _ := strconv.Atoi(exps)
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1 // value = 0.digits × 10^decpt, as in Python's format_float_short
	var out strings.Builder
	if neg {
		out.WriteByte('-')
	}
	if decpt > -4 && decpt <= 16 {
		switch {
		case decpt <= 0:
			out.WriteString("0.")
			out.WriteString(strings.Repeat("0", -decpt))
			out.WriteString(digits)
		case decpt >= len(digits):
			out.WriteString(digits)
			out.WriteString(strings.Repeat("0", decpt-len(digits)))
			out.WriteString(".0")
		default:
			out.WriteString(digits[:decpt])
			out.WriteByte('.')
			out.WriteString(digits[decpt:])
		}
		return out.String()
	}
	out.WriteByte(digits[0])
	if len(digits) > 1 {
		out.WriteByte('.')
		out.WriteString(digits[1:])
	}
	out.WriteByte('e')
	if exp < 0 {
		out.WriteByte('-')
		exp = -exp
	} else {
		out.WriteByte('+')
	}
	if exp < 10 {
		out.WriteByte('0')
	}
	out.WriteString(strconv.Itoa(exp))
	return out.String()
}
