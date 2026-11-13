package personcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"go.yaml.in/yaml/v3"
)

// Output formats (-o).
const (
	FormatTable = "table"
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
	FormatYAML  = "yaml"
)

func checkFormat(f string) error {
	switch f {
	case FormatTable, FormatJSON, FormatJSONL, FormatYAML:
		return nil
	}
	return fmt.Errorf("-o is table, json, jsonl or yaml, not %q", f)
}

// table writes aligned columns.
func table(w io.Writer, head []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, r := range rows {
		for i := range r {
			r[i] = clean(r[i])
		}
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

// clean keeps control characters of a server-supplied value out of the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// kv writes "key  value" lines aligned.
func kv(w io.Writer, rows [][2]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r[0], clean(r[1]))
	}
	tw.Flush()
}

// emit writes raw (one JSON document, as the API sent it) in the format; for jsonl, items names the array to write
// one line per element of ("" writes the document as one line). It reports whether it wrote (false: table).
func emit(w io.Writer, format string, raw json.RawMessage, items string) (bool, error) {
	switch format {
	case FormatJSON:
		var b bytes.Buffer
		if err := json.Indent(&b, raw, "", "  "); err != nil {
			return true, err
		}
		b.WriteByte('\n')
		_, err := w.Write(b.Bytes())
		return true, err
	case FormatJSONL:
		if items != "" {
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(raw, &doc); err != nil {
				return true, err
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(doc[items], &arr); err != nil {
				return true, err
			}
			for _, it := range arr {
				if err := compactLine(w, it); err != nil {
					return true, err
				}
			}
			return true, nil
		}
		return true, compactLine(w, raw)
	case FormatYAML:
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return true, err
		}
		b, err := yaml.Marshal(v)
		if err != nil {
			return true, err
		}
		_, err = w.Write(b)
		return true, err
	}
	return false, nil
}

func compactLine(w io.Writer, raw json.RawMessage) error {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return err
	}
	b.WriteByte('\n')
	_, err := w.Write(b.Bytes())
	return err
}

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case nil:
		return ""
	case float64:
		return fmt.Sprintf("%.0f", v)
	case bool:
		return fmt.Sprint(v)
	}
	b, _ := json.Marshal(m[k])
	return string(b)
}

func sub(m map[string]any, k string) map[string]any {
	s, _ := m[k].(map[string]any)
	return s
}
