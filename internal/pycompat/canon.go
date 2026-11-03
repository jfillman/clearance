// Package pycompat reproduces the few Python behaviours the gate's records and digests depend on byte for byte:
// json.dumps (sort_keys, separators, ensure_ascii, float repr), fnmatch.fnmatchcase, str()/repr() of JSON values,
// and datetime.isoformat. Values are what encoding/json produces with UseNumber: string, bool, json.Number,
// float64, []any, map[string]any, nil (int, int64, *big.Int and float64 are accepted too).
//
// R-1b's record package owns the chain's canonical form; this is the same encoding for the digests the gate
// computes itself (args_sha256, the clearance.yaml digest, the rendered tree's digest). Merge the two when R-1 lands.
package pycompat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Options select json.dumps' arguments.
type Options struct {
	// ASCII is ensure_ascii=True: every character outside space..~ is escaped as \uXXXX.
	ASCII bool
	// Spaced is the default separators (", ", ": "); false is separators=(",", ":").
	Spaced bool
}

// Canonical is audit.canonical: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func Canonical(v any) ([]byte, error) { return Dumps(v, Options{}) }

// Dumps is json.dumps(v, sort_keys=True, ...) with the given options.
func Dumps(v any, o Options) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v, o); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ArgsDigest is audit.args_digest: the sha256 of the canonical JSON of v. v may be any Go value encoding/json
// can marshal; it is normalised through JSON first, so a struct digests as its JSON object.
func ArgsDigest(v any) string {
	n, err := Normalize(v)
	if err != nil {
		return ""
	}
	b, err := Canonical(n)
	if err != nil {
		return ""
	}
	return SHA256Hex(b)
}

// SHA256Hex is hashlib.sha256(b).hexdigest().
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Normalize turns any marshalable Go value into the generic JSON value encoding/json decodes (with UseNumber).
func Normalize(v any) (any, error) {
	switch v.(type) {
	case nil, string, bool, json.Number, float64, map[string]any, []any:
		return v, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Decode(bytes.NewReader(raw))
}

// Decode reads exactly one JSON value (numbers as json.Number), refusing trailing data as json.loads does.
func Decode(r io.Reader) (any, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

func encode(b *bytes.Buffer, v any, o Options) error {
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
		writeString(b, x, o.ASCII)
	case json.Number:
		s, err := NumberString(x)
		if err != nil {
			return err
		}
		if s == "inf" || s == "-inf" || s == "nan" {
			b.WriteString(map[string]string{"inf": "Infinity", "-inf": "-Infinity", "nan": "NaN"}[s])
		} else {
			b.WriteString(s)
		}
	case float64:
		b.WriteString(jsonFloat(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case *big.Int:
		b.WriteString(x.String())
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sep(b, o, ',')
			}
			if err := encode(b, e, o); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sep(b, o, ',')
			}
			writeString(b, e, o.ASCII)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sep(b, o, ',')
			}
			writeString(b, k, o.ASCII)
			sep(b, o, ':')
			if err := encode(b, x[k], o); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		n, err := Normalize(v)
		if err != nil {
			return err
		}
		if _, same := n.(map[string]any); !same {
			if _, same = n.([]any); !same {
				return fmt.Errorf("pycompat: cannot encode %T", v)
			}
		}
		return encode(b, n, o)
	}
	return nil
}

func sep(b *bytes.Buffer, o Options, c byte) {
	b.WriteByte(c)
	if o.Spaced {
		b.WriteByte(' ')
	}
}

func writeString(b *bytes.Buffer, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
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
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case ascii && (r > 0x7e || r == utf8.RuneError):
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// ASCIIEscape rewrites every non-ASCII character in JSON text as \uXXXX (what ensure_ascii=True adds to output
// encoding/json produced with SetEscapeHTML(false)). Only string contents can hold them, so a byte-level pass is safe.
func ASCIIEscape(in []byte) []byte {
	var b bytes.Buffer
	for len(in) > 0 {
		r, n := utf8.DecodeRune(in)
		switch {
		case r == 0x7f:
			b.WriteString(`\u007f`)
		case r < 0x80:
			b.WriteByte(byte(r))
		case r > 0xffff:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		in = in[n:]
	}
	return b.Bytes()
}

// IsInt says whether a json.Number is a JSON integer literal (Python's json.loads makes it an int).
func IsInt(n json.Number) bool { return !strings.ContainsAny(string(n), ".eE") }

// NumberString is Python's str() of the number json.loads would make of n: an int's decimal, a float's repr
// ("inf", "-inf" or "nan" for the out-of-range ones).
func NumberString(n json.Number) (string, error) {
	if IsInt(n) {
		z, ok := new(big.Int).SetString(string(n), 10)
		if !ok {
			return "", fmt.Errorf("pycompat: bad number %q", n)
		}
		return z.String(), nil
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		var ne *strconv.NumError
		if !(asNumErr(err, &ne) && ne.Err == strconv.ErrRange) {
			return "", err
		}
	}
	return FloatRepr(f), nil
}

func asNumErr(err error, target **strconv.NumError) bool {
	ne, ok := err.(*strconv.NumError)
	if ok {
		*target = ne
	}
	return ok
}

func jsonFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case math.IsNaN(f):
		return "NaN"
	}
	return FloatRepr(f)
}

// FloatRepr is Python's repr(float): the shortest round-tripping digits, fixed notation when the decimal point
// falls in -4 < decpt <= 16 (with ".0" for an integral value), else d.ddde±XX.
func FloatRepr(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // -d.ddde±dd
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mant, expS, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expS)
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1
	var out string
	if -4 < decpt && decpt <= 16 {
		switch {
		case decpt <= 0:
			out = "0." + strings.Repeat("0", -decpt) + digits
		case decpt >= len(digits):
			out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		default:
			out = digits[:decpt] + "." + digits[decpt:]
		}
	} else {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		e := decpt - 1
		sign := "+"
		if e < 0 {
			sign, e = "-", -e
		}
		out = fmt.Sprintf("%se%s%02d", m, sign, e)
	}
	if neg {
		out = "-" + out
	}
	return out
}
