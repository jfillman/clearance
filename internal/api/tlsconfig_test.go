package api

import "testing"

func TestTheTLSListenerSettings(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := map[string]string{"CLEARANCE_API_DSN": "postgres://x"}
	with := func(kv map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range kv {
			m[k] = v
		}
		return m
	}
	cfg, err := FromEnv(env(base))
	if err != nil || cfg.TLS.Addr != "" || cfg.Listen != ":8080" {
		t.Fatalf("off by default: %+v %v", cfg.TLS, err)
	}
	tls := map[string]string{"CLEARANCE_TLS_LISTEN": ":8443", "CLEARANCE_TLS_CERT_FILE": "/etc/tls/tls.crt", "CLEARANCE_TLS_KEY_FILE": "/etc/tls/tls.key"}
	if cfg, err = FromEnv(env(with(tls))); err != nil || cfg.TLS.Addr != ":8443" || cfg.TLS.KeyFile != "/etc/tls/tls.key" || cfg.Listen != ":8080" {
		t.Fatalf("on: %+v %v", cfg.TLS, err)
	}
	off := with(tls)
	off["CLEARANCE_LISTEN"] = "off"
	if cfg, err = FromEnv(env(off)); err != nil || cfg.Listen != "off" {
		t.Fatalf("plain off: %v", err)
	}
	for _, bad := range []map[string]string{{"CLEARANCE_TLS_LISTEN": ":8443"}, {"CLEARANCE_LISTEN": "off"},
		{"CLEARANCE_TLS_CERT_FILE": "/c", "CLEARANCE_TLS_KEY_FILE": "/k"}} {
		if _, err := FromEnv(env(with(bad))); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
