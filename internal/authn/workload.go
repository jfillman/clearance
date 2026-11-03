package authn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// SADir is where the kubelet mounts the pod's service-account token and the cluster CA.
const SADir = "/var/run/secrets/kubernetes.io/serviceaccount"

// MaxTokenReviewBytes caps the API server's TokenReview response.
const MaxTokenReviewBytes = 1 << 20

// WorkloadAuthenticator is a service-account token, verified by TokenReview for Audience. Clearance's own identity
// needs create on tokenreviews (the system:auth-delegator ClusterRole). TokenFile and CAFile are re-read on every
// call, because the kubelet rotates the projected token. Do, when set, replaces the HTTPS client (tests).
type WorkloadAuthenticator struct {
	Audience  string
	API       string
	TokenFile string
	CAFile    string
	Timeout   time.Duration
	Do        func(*http.Request) (*http.Response, error)

	mu     sync.Mutex
	ca     []byte
	client *http.Client
}

// NewWorkloadAuthenticator reviews tokens for audience with the in-cluster API server and service-account files.
func NewWorkloadAuthenticator(audience string) *WorkloadAuthenticator {
	return &WorkloadAuthenticator{Audience: audience, API: "https://kubernetes.default.svc",
		TokenFile: SADir + "/token", CAFile: SADir + "/ca.crt", Timeout: 10 * time.Second}
}

// httpClient is a client trusting exactly the CA file's certificates, rebuilt only when the file changes.
func (a *WorkloadAuthenticator) httpClient() (*http.Client, error) {
	ca, err := os.ReadFile(a.CAFile)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil && bytes.Equal(ca, a.ca) {
		return a.client, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA certificate in " + a.CAFile)
	}
	a.ca = ca
	a.client = &http.Client{Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second,
	}}
	return a.client, nil
}

type tokenReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       tokenReviewSpec   `json:"spec"`
	Status     tokenReviewStatus `json:"status,omitzero"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type tokenReviewStatus struct {
	Authenticated bool     `json:"authenticated"`
	Audiences     []string `json:"audiences"`
	User          struct {
		Username string `json:"username"`
	} `json:"user"`
}

func (a *WorkloadAuthenticator) review(ctx context.Context, token string) (tokenReviewStatus, error) {
	own, err := os.ReadFile(a.TokenFile)
	if err != nil {
		return tokenReviewStatus{}, err
	}
	body, err := json.Marshal(tokenReview{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview",
		Spec: tokenReviewSpec{Token: token, Audiences: []string{a.Audience}}})
	if err != nil {
		return tokenReviewStatus{}, err
	}
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(a.API, "/")+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return tokenReviewStatus{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	do := a.Do
	if do == nil {
		c, err := a.httpClient()
		if err != nil {
			return tokenReviewStatus{}, err
		}
		do = c.Do
	}
	resp, err := do(req)
	if err != nil {
		return tokenReviewStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return tokenReviewStatus{}, fmt.Errorf("TokenReview: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenReviewBytes+1))
	if err != nil {
		return tokenReviewStatus{}, err
	}
	if len(raw) > MaxTokenReviewBytes {
		return tokenReviewStatus{}, errors.New("TokenReview: response too large")
	}
	var out tokenReview
	if err := json.Unmarshal(raw, &out); err != nil {
		return tokenReviewStatus{}, err
	}
	return out.Status, nil
}

// Authenticate reviews token. The API server unreachable is a refusal, never a pass.
func (a *WorkloadAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	st, err := a.review(ctx, token)
	if err != nil {
		return Principal{}, refuse("token review failed")
	}
	if !st.Authenticated || !slices.Contains(st.Audiences, a.Audience) {
		return Principal{}, refuse("token not authenticated for this audience")
	}
	name := st.User.Username
	if !strings.HasPrefix(name, SAPrefix) || strings.Count(name, ":") != 3 {
		return Principal{}, refuse("not a service-account token")
	}
	ns, sa, _ := strings.Cut(name[len(SAPrefix):], ":")
	return Principal{ID: ns + "/" + sa, Kind: KindServiceAccount}, nil
}
