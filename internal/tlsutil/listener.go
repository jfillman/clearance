package tlsutil

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

// Off, as the plain listener's address (CLEARANCE_LISTEN=off), means no plain-http listener at all. It needs a TLS one.
const Off = "off"

// Listener is the optional https listener of a server: where, and the files its certificate comes from.
type Listener struct {
	Addr     string // CLEARANCE_TLS_LISTEN, e.g. ":8443"; "" is off
	CertFile string // CLEARANCE_TLS_CERT_FILE
	KeyFile  string // CLEARANCE_TLS_KEY_FILE
}

// ListenerFromEnv reads the three CLEARANCE_TLS_* variables and checks them against the plain listen address:
// all three or none; the plain listener may be "off" only with TLS on.
func ListenerFromEnv(getenv func(string) string, plain string) (Listener, error) {
	l := Listener{Addr: getenv("CLEARANCE_TLS_LISTEN"), CertFile: getenv("CLEARANCE_TLS_CERT_FILE"), KeyFile: getenv("CLEARANCE_TLS_KEY_FILE")}
	if l.Addr == "" && (l.CertFile != "" || l.KeyFile != "") {
		return l, errors.New("CLEARANCE_TLS_CERT_FILE and CLEARANCE_TLS_KEY_FILE need CLEARANCE_TLS_LISTEN")
	}
	if l.Addr != "" {
		if l.CertFile == "" || l.KeyFile == "" {
			return l, errors.New("CLEARANCE_TLS_LISTEN needs CLEARANCE_TLS_CERT_FILE and CLEARANCE_TLS_KEY_FILE")
		}
		if _, _, err := net.SplitHostPort(l.Addr); err != nil {
			return l, fmt.Errorf("CLEARANCE_TLS_LISTEN %q is host:port or :port", l.Addr)
		}
		if l.Addr == plain {
			return l, errors.New("CLEARANCE_TLS_LISTEN and CLEARANCE_LISTEN are the same address")
		}
	}
	if plain == Off && l.Addr == "" {
		return l, errors.New("CLEARANCE_LISTEN=off needs CLEARANCE_TLS_LISTEN: with both off nothing would serve")
	}
	return l, nil
}

// Listen opens the https listener; nil, nil when Addr is "". An unreadable certificate or key is an error.
func (l Listener) Listen() (net.Listener, error) {
	if l.Addr == "" {
		return nil, nil
	}
	s, err := NewServer(l.CertFile, l.KeyFile)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return nil, fmt.Errorf("tls listen %s: %w", l.Addr, err)
	}
	return tls.NewListener(ln, s.Config()), nil
}
