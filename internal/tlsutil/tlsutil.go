// Package tlsutil is the optional in-cluster TLS of the core and the API, and the CA setting of their clients.
//
// Server side: Server serves a certificate and key from files and re-reads them when they change on disk (cert-manager
// rewrites the Secret's files on renewal), so a renewal needs no restart. Client side: RootCAs and ClientConfig build a
// *tls.Config that trusts the system roots plus one PEM file, for a private in-cluster CA; with no file they return nil
// and the client keeps the system roots. Nothing here turns verification off.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// reloadEvery bounds how often a handshake looks at the files' modification times.
const reloadEvery = 10 * time.Second

// Server holds the serving certificate and reloads it when the files change.
type Server struct {
	certFile, keyFile string
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	certMod time.Time
	keyMod  time.Time
	checked time.Time
}

// NewServer loads certFile and keyFile once; an unreadable or mismatched pair is an error (refuse to start).
func NewServer(certFile, keyFile string) (*Server, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("tls: a certificate file and a key file are both required")
	}
	s := &Server{certFile: certFile, keyFile: keyFile, now: time.Now}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) load() error {
	cm, err := modTime(s.certFile)
	if err != nil {
		return err
	}
	km, err := modTime(s.keyFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("tls: loading the certificate and key: %w", err)
	}
	s.cert, s.certMod, s.keyMod, s.checked = &c, cm, km, s.now()
	return nil
}

func modTime(p string) (time.Time, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return time.Time{}, fmt.Errorf("tls: %w", err)
	}
	return fi.ModTime(), nil
}

// GetCertificate is tls.Config.GetCertificate. When the files changed it loads the new pair; a failed reload (a
// half-written pair, say) keeps serving the last good certificate and tries again at the next check.
func (s *Server) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.checked) >= reloadEvery {
		s.checked = s.now()
		cm, e1 := modTime(s.certFile)
		km, e2 := modTime(s.keyFile)
		if e1 == nil && e2 == nil && (!cm.Equal(s.certMod) || !km.Equal(s.keyMod)) {
			_ = s.load() // keep the old certificate on error
		}
	}
	return s.cert, nil
}

// Config is the listener's tls.Config: TLS 1.2 or later, the reloading certificate.
func (s *Server) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.GetCertificate}
}

// RootCAs returns the system roots plus the certificates in caFile. caFile "" returns nil (use the default roots).
// An unreadable file or one with no certificate is an error.
func RootCAs(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls: reading the CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: %s holds no PEM certificate", caFile)
	}
	return pool, nil
}

// ClientConfig is a tls.Config for a client that trusts caFile besides the system roots; nil when caFile is "".
func ClientConfig(caFile string) (*tls.Config, error) {
	pool, err := RootCAs(caFile)
	if err != nil || pool == nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
}
