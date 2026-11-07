package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponse caps what a Fulcio or Rekor answer may be.
const maxResponse = 1 << 20

// DefaultTimeout is each Fulcio or Rekor call's deadline.
const DefaultTimeout = 20 * time.Second

// CheckURL accepts an https URL, or an http one only for a loopback host (tests, a local lab) or an in-cluster Service
// name (<service>.<namespace>.svc, optionally .cluster.local: the platform's own Fulcio and Rekor, which serve plain
// HTTP inside the cluster), with no credentials, query or fragment.
func CheckURL(name, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be an https URL with a host and no credentials, query or fragment", name)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			host = u.Host
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); host != "localhost" && (ip == nil || !ip.IsLoopback()) && !clusterService(host) {
			return nil, fmt.Errorf("%s must be https (http is for loopback and in-cluster Service names only)", name)
		}
	default:
		return nil, fmt.Errorf("%s must be an https URL", name)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// clusterService reports whether host is <service>.<namespace>.svc or <service>.<namespace>.svc.cluster.local.
func clusterService(host string) bool {
	h := strings.TrimSuffix(host, ".cluster.local")
	if !strings.HasSuffix(h, ".svc") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(h, ".svc"), ".")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// postJSON POSTs body as JSON and decodes a 2xx JSON answer into out (when not nil); anything else is an error that
// names the status and a bounded part of the body, never the request.
func postJSON(ctx context.Context, hc *http.Client, target string, header map[string]string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", redact(target), errors.Unwrap(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return fmt.Errorf("POST %s: the answer is over %d bytes", redact(target), maxResponse)
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("POST %s: %s: %s", redact(target), resp.Status, msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("POST %s: the answer is not the JSON expected: %w", redact(target), err)
	}
	return nil
}

func redact(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return "(url)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}
