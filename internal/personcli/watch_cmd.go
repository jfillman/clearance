package personcli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type sseEvent struct {
	ID, Name string
	Data     []byte
}

// readEvents parses a text/event-stream, calling fn per event until the stream ends or fn says stop.
func readEvents(r *bufio.Scanner, fn func(sseEvent) bool) error {
	var ev sseEvent
	var data []string
	for r.Scan() {
		line := r.Text()
		switch {
		case line == "":
			if len(data) > 0 {
				ev.Data = []byte(strings.Join(data, "\n"))
				if !fn(ev) {
					return nil
				}
			}
			ev, data = sseEvent{}, nil
		case strings.HasPrefix(line, ":"):
		default:
			k, v, _ := strings.Cut(line, ":")
			v = strings.TrimPrefix(v, " ")
			switch k {
			case "id":
				ev.ID = v
			case "event":
				ev.Name = v
			case "data":
				data = append(data, v)
			}
		}
	}
	return r.Err()
}

// Watch is `clearance watch`: GET /v1/stream, filtered, reconnecting with Last-Event-ID when the server ends it
// (it does every 10 minutes) or the connection drops, and dropping events already shown.
func (e *Env) Watch(ctx context.Context, args []string) int {
	var types, app, change, tool string
	var count int
	var after string
	s, pos, ee := e.begin("watch", "[--types records,clearances] [--app A] [--change ID] [--tool T] [--count N]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&types, "types", "", "records, clearances or both (default both)")
		fs.StringVar(&app, "app", "", "only events about this app")
		fs.StringVar(&change, "change", "", "only events about this change")
		fs.StringVar(&tool, "tool", "", "only this tool (deploy.clear, ...)")
		fs.IntVar(&count, "count", 0, "stop after this many events (default: until interrupted)")
		fs.StringVar(&after, "after", "", "resume after this seq (default: from now)")
	})
	if ee != nil {
		return e.finish("watch", ee)
	}
	if len(pos) > 0 {
		return e.finish("watch", s.usageErr())
	}
	return e.finish("watch", func() error {
		if s.format == FormatJSON { // a stream is lines
			s.format = FormatJSONL
		}
		c, err := s.client(true)
		if err != nil {
			return err
		}
		_, end, _ := s.token()
		q := url.Values{}
		setIf(q, "types", types)
		last := after
		lastSeq := map[string]int64{}
		shown := 0
		failures := 0
		backoff := time.Second
		for ctx.Err() == nil && (count == 0 || shown < count) {
			if !end.IsZero() && !e.Now().Before(end) {
				return fail(ExitUnauthorized, "the token expired: run `%s login` and watch again (--after %s resumes)", e.prog(), last)
			}
			qq := url.Values{}
			for k, v := range q {
				qq[k] = v
			}
			if last != "" {
				qq.Set("after", last)
			}
			body, err := c.Stream(ctx, "/v1/stream", qq, last)
			if err != nil {
				var ae *APIError
				if ctx.Err() != nil {
					return nil
				}
				if errors.As(err, &ae) && ae.Status < 500 && ae.Status != 429 {
					return err
				}
				if failures++; failures > 5 && last == "" {
					return err
				}
				fmt.Fprintf(e.Stderr, "%s watch: %v; retrying\n", e.prog(), mapError(err).msg)
				if e.Sleep(ctx, backoff) != nil {
					return nil
				}
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			failures, backoff = 0, time.Second
			sc := bufio.NewScanner(body)
			sc.Buffer(make([]byte, 64<<10), 4<<20)
			_ = readEvents(sc, func(ev sseEvent) bool {
				if n, err := strconv.ParseInt(ev.ID, 10, 64); err == nil {
					if n <= lastSeq[ev.Name] && lastSeq[ev.Name] != 0 {
						return true // sent again after a reconnect
					}
					lastSeq[ev.Name] = n
					last = ev.ID
				}
				if !watchMatch(ev, app, change, tool) {
					return true
				}
				printEvent(e, s.format, ev)
				shown++
				return count == 0 || shown < count
			})
			body.Close()
			if count != 0 && shown >= count {
				break
			}
			if ctx.Err() == nil {
				if e.Sleep(ctx, time.Second) != nil {
					return nil
				}
			}
		}
		return nil
	}())
}

func watchMatch(ev sseEvent, app, change, tool string) bool {
	var m map[string]any
	if json.Unmarshal(ev.Data, &m) != nil {
		return false
	}
	ch := sub(m, "change")
	evApp, evChange := str(m, "app"), ""
	if ch != nil {
		evChange = str(ch, "id")
		if evApp == "" {
			evApp = str(ch, "app")
		}
	}
	if app != "" && !strings.EqualFold(evApp, app) {
		return false
	}
	if change != "" && evChange != change {
		return false
	}
	return tool == "" || str(m, "tool") == tool
}

func printEvent(e *Env, format string, ev sseEvent) {
	switch format {
	case FormatJSONL, FormatJSON:
		_ = compactLine(e.Stdout, ev.Data)
	case FormatYAML:
		_, _ = emit(e.Stdout, FormatYAML, ev.Data, "")
		fmt.Fprintln(e.Stdout, "---")
	default:
		var m map[string]any
		_ = json.Unmarshal(ev.Data, &m)
		subject := str(m, "target")
		if ch := sub(m, "change"); ch != nil {
			subject = fmt.Sprintf("%s %s/%s tier %s %s", str(ch, "id"), str(ch, "app"), str(ch, "env"), str(ch, "tier"), str(ch, "state"))
		} else if p := str(m, "principal"); p != "" {
			subject = p + " " + subject
		}
		fmt.Fprintf(e.Stdout, "%s  %-10s %-6s %-22s %s\n", clock(m, "ts"), ev.Name, str(m, "seq"), str(m, "tool"), clean(subject))
	}
}
