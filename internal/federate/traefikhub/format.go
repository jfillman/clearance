package traefikhub

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Limits on what the adapter reads.
const (
	// MaxLine caps one log line. Hub's decision lines are a few hundred bytes; an access line with kept headers a
	// few KiB.
	MaxLine = 64 << 10
	// MaxLines caps the lines read from one file in one run.
	MaxLines = 1_000_000
)

// Middleware types whose lines are decision records.
var decisionTypes = map[string]bool{"authzen": true, "authzen-mcp": true}

// Decision is one decision record (the Hub log), as published.
type Decision struct {
	Level             string `json:"level"`
	MiddlewareName    string `json:"middlewareName"`
	MiddlewareType    string `json:"middlewareType"`
	Decision          string `json:"decision"` // allow, deny or bypass
	Policy            string `json:"policy"`   // authzen-mcp only
	Reason            string `json:"reason"`
	Error             string `json:"error"`
	TraceID           string `json:"trace_id"`
	TransparencyLogID string `json:"transparency_log_id"`
	GatewayID         string `json:"gateway_id"`
	Time              string `json:"time"`
	Message           string `json:"message"`

	// LineSHA256 is the SHA-256 of the line as read (without its newline).
	LineSHA256 string `json:"-"`
}

// Access is one access record (the access log): the fields the adapter reads, plus the kept request headers.
type Access struct {
	RequestHost       string `json:"RequestHost"`
	RequestMethod     string `json:"RequestMethod"`
	RequestPath       string `json:"RequestPath"`
	RouterName        string `json:"RouterName"`
	ClientUsername    string `json:"ClientUsername"`
	DownstreamStatus  *int   `json:"DownstreamStatus"`
	TraceID           string `json:"trace_id"`
	TraceIDAlt        string `json:"TraceId"`
	TransparencyLogID string `json:"transparency_log_id"`

	// Headers are the request_<Header> fields, keyed by the header name in lower case.
	Headers map[string]string `json:"-"`
	// LineSHA256 is the SHA-256 of the line as read (without its newline).
	LineSHA256 string `json:"-"`
}

// Trace is the access record's trace id: trace_id, else TraceId.
func (a *Access) Trace() string {
	if a.TraceID != "" {
		return a.TraceID
	}
	return a.TraceIDAlt
}

// Header is a kept request header's value ("" when not kept).
func (a *Access) Header(name string) string { return a.Headers[strings.ToLower(name)] }

// ReadStats counts what a read skipped.
type ReadStats struct {
	Lines    int `json:"lines"`
	Skipped  int `json:"skipped"`  // not a JSON object, or a decision line without a decision
	TooLong  int `json:"too_long"` // over MaxLine
	NotOurs  int `json:"not_ours"` // a Hub log line that is not a decision record
	Accepted int `json:"accepted"`
}

// ErrTooManyLines is returned when a file has more than MaxLines lines.
var ErrTooManyLines = errors.New("traefikhub: more than MaxLines lines")

// eachLine calls f on every non-blank line of r (without its newline), counting and skipping lines over MaxLine.
func eachLine(r io.Reader, st *ReadStats, f func([]byte)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, err := readLine(br)
		if err != nil && err != io.EOF {
			return fmt.Errorf("traefikhub: read: %w", err)
		}
		line = bytes.TrimRight(line, "\r")
		if tooLong || len(bytes.TrimSpace(line)) > 0 {
			st.Lines++
			if st.Lines > MaxLines {
				return ErrTooManyLines
			}
			if tooLong {
				st.TooLong++
			} else {
				f(line)
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// readLine reads one line without its newline. A line over MaxLine is read to its end and dropped (tooLong).
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			limit := MaxLine
			if bytes.HasSuffix(chunk, []byte("\n")) {
				limit++ // the newline; a last line at EOF has none
			}
			if len(line)+len(chunk) > limit {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return bytes.TrimSuffix(line, []byte("\n")), tooLong, err
	}
}

func lineSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ParseDecisions reads the Hub log and returns its decision records; every other line is counted, not returned.
func ParseDecisions(r io.Reader) ([]Decision, ReadStats, error) {
	var out []Decision
	var st ReadStats
	err := eachLine(r, &st, func(line []byte) {
		var d Decision
		if json.Unmarshal(line, &d) != nil {
			st.Skipped++
			return
		}
		if !decisionTypes[d.MiddlewareType] {
			st.NotOurs++
			return
		}
		if d.Decision != "allow" && d.Decision != "deny" && d.Decision != "bypass" {
			// A PDP or mapping failure is an error line with no decision: the access record (a 500) is all
			// there is, and it is not a decision.
			st.Skipped++
			return
		}
		d.LineSHA256 = lineSum(line)
		st.Accepted++
		out = append(out, d)
	})
	return out, st, err
}

// ParseAccess reads the access log and returns the records that carry a trace id (only those can be joined).
func ParseAccess(r io.Reader) ([]Access, ReadStats, error) {
	var out []Access
	var st ReadStats
	err := eachLine(r, &st, func(line []byte) {
		var a Access
		var raw map[string]json.RawMessage
		if json.Unmarshal(line, &raw) != nil || json.Unmarshal(line, &a) != nil {
			st.Skipped++
			return
		}
		if a.Trace() == "" {
			st.NotOurs++
			return
		}
		for k, v := range raw {
			name, ok := strings.CutPrefix(k, "request_")
			if !ok || name == "" {
				continue
			}
			var s string
			if json.Unmarshal(v, &s) == nil {
				if a.Headers == nil {
					a.Headers = map[string]string{}
				}
				a.Headers[strings.ToLower(name)] = s
			}
		}
		a.LineSHA256 = lineSum(line)
		st.Accepted++
		out = append(out, a)
	})
	return out, st, err
}
