package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// doctorStubCore answers /healthz and the authenticated read the way the core does: 401 without the right bearer, 404 for a
// change that does not exist. It records whether anything but a GET arrived.
type doctorStubCore struct {
	srv    *httptest.Server
	nonGet int
	want   string // the bearer it accepts; "" accepts any
	status int    // /v1/clearances/ status for an accepted token (default 404)
}

func newDoctorStubCore(t *testing.T, want string) *doctorStubCore {
	t.Helper()
	f := &doctorStubCore{want: want, status: http.StatusNotFound}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			f.nonGet++
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/healthz":
			w.Write([]byte(`{"ok":true}`))
		case strings.HasPrefix(r.URL.Path, "/v1/clearances/"):
			if f.want != "" && r.Header.Get("Authorization") != "Bearer "+f.want {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"the token is not valid"}`))
				return
			}
			w.WriteHeader(f.status)
			w.Write([]byte(`{"error":"no such change"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// doctorFixture is a complete, healthy fake environment; a test breaks one thing.
type doctorFixture struct {
	env    map[string]string
	dir    string
	token  string
	tools  map[string]string // tool name -> version output ("" = missing)
	plugin string
	server string
	core   *doctorStubCore
	free   int64  // free bytes the fake volume reports (0: unknown)
	memMax string // the container's cgroup memory.max ("": unreadable)
}

func newDoctorFixture(t *testing.T) *doctorFixture {
	t.Helper()
	dir := t.TempDir()
	f := &doctorFixture{dir: dir, token: filepath.Join(dir, "token"), plugin: filepath.Join(dir, "plugins"), server: filepath.Join(dir, "argocd-cmp-server"),
		tools: map[string]string{"git": "git version 2.45.0", "helm": "v4.2.1", "kustomize": "v5.8.1"}}
	if err := os.WriteFile(f.token, []byte("tok-secret-value\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.plugin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.server, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	f.free = 8 << 30
	f.core = newDoctorStubCore(t, "tok-secret-value")
	f.env = map[string]string{
		"CLEARANCE_URL": f.core.srv.URL, "CLEARANCE_TOKEN_FILE": f.token, "CLEARANCE_CMP_CACHE_DIR": filepath.Join(dir, "cache"),
		"CLEARANCE_CHART_REPOS": "https://git.example.test/org/charts.git, oci://registry.example.test/org/charts",
		"CLEARANCE_WAIT_IMAGE":  "registry.example.test/clearance-wait:v1", NetnsEnv: "off", FSSandboxEnv: "off",
	}
	return f
}

func (f *doctorFixture) run(t *testing.T) ([]Check, string, int) {
	t.Helper()
	env := DoctorEnv{
		Get: func(k string) string { return f.env[k] },
		LookPath: func(n string) (string, error) {
			if f.tools[n] == "" {
				return "", exec.ErrNotFound
			}
			return "/usr/bin/" + n, nil
		},
		Run: func(_ context.Context, path string, _ ...string) (string, error) {
			return f.tools[filepath.Base(path)] + "\nsecond line", nil
		},
		PluginDir: f.plugin, CmpServer: f.server, Timeout: 2 * time.Second,
		FreeBytes: func(string) (int64, bool) { return f.free, f.free > 0 },
		ReadFile: func(p string) ([]byte, error) {
			if f.memMax == "" {
				return nil, os.ErrNotExist
			}
			return []byte(f.memMax + "\n"), nil
		},
	}
	checks := Doctor(context.Background(), env)
	var out bytes.Buffer
	code := RunDoctor(context.Background(), env, &out)
	if strings.Contains(out.String(), "tok-secret-value") {
		t.Fatalf("the token was printed:\n%s", out.String())
	}
	return checks, out.String(), code
}

// find returns the checks with that name.
func doctorFind(cs []Check, name string) []Check {
	var out []Check
	for _, c := range cs {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func doctorWant(t *testing.T, cs []Check, name, level, contains string) {
	t.Helper()
	got := doctorFind(cs, name)
	for _, c := range got {
		if c.Level == level && strings.Contains(c.Msg+" "+c.Fix, contains) {
			return
		}
	}
	t.Fatalf("no %s check at %s containing %q; got %+v", name, level, contains, got)
}

// rewrite replaces the token file's content (it is mode 0440, so it cannot be opened for writing).
func rewrite(p, content string) {
	os.Remove(p)
	os.WriteFile(p, []byte(content), 0o440)
}

func TestDoctorAllGood(t *testing.T) {
	f := newDoctorFixture(t)
	cs, out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, c := range cs {
		if c.Level != levelOK {
			t.Errorf("%s is %s: %s", c.Name, c.Level, c.Msg)
		}
	}
	for _, name := range []string{"settings", "token", "core", "core-auth", "chart-repos", "cache", "chart-cache", "render-cache", "git", "helm", "kustomize", "netns", "fs-sandbox", "render-limits", "plugin-socket", "cmp-server"} {
		if len(doctorFind(cs, name)) == 0 {
			t.Errorf("no %s check", name)
		}
	}
	doctorWant(t, cs, "helm", levelOK, "v4.2.1")
	if f.core.nonGet != 0 {
		t.Errorf("doctor sent %d non-GET requests to the core", f.core.nonGet)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "doctor: 12 ok, 0 warn, 0 fail") && !strings.Contains(out, "0 warn, 0 fail") {
		t.Errorf("summary line: %s", out)
	}
}

func TestDoctorReportsEverySettingProblemNotJustTheFirst(t *testing.T) {
	f := newDoctorFixture(t)
	f.env["CLEARANCE_URL"] = "ftp://nope"
	f.env["CLEARANCE_WAIT_HOST_ALIAS"] = "not-an-alias"
	f.env["CLEARANCE_WAIT_IMAGE"] = "bad image"
	f.env["CLEARANCE_CHART_REPOS"] = "/local/path https://git.example.test/org/charts"
	f.env[NetnsEnv] = "sometimes"
	f.env["CLEARANCE_CMP_CACHE_TTL"] = "soon"
	cs, _, code := f.run(t)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for _, s := range []string{"CLEARANCE_URL", "CLEARANCE_WAIT_HOST_ALIAS", "CLEARANCE_WAIT_IMAGE", "CLEARANCE_CHART_REPOS", NetnsEnv, "CLEARANCE_CMP_CACHE_TTL"} {
		doctorWant(t, cs, "setting", levelFail, s)
	}
}

func TestDoctorRequiredSettingMissing(t *testing.T) {
	f := newDoctorFixture(t)
	delete(f.env, "CLEARANCE_URL")
	cs, _, code := f.run(t)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	doctorWant(t, cs, "setting", levelFail, "CLEARANCE_URL is required")
	doctorWant(t, cs, "core", levelFail, "not checked")
}

func TestDoctorPerRunVariablesAreNotRequired(t *testing.T) {
	f := newDoctorFixture(t)
	cs, _, _ := f.run(t)
	for _, c := range doctorFind(cs, "setting") {
		t.Errorf("unexpected setting problem: %s", c.Msg)
	}
	// ...but a set one is still checked.
	f.env["PARAM_APP"] = "Not_A_Label"
	cs, _, _ = f.run(t)
	doctorWant(t, cs, "setting", levelFail, "PARAM_APP")
}

func TestDoctorWaitImageUnsetWarns(t *testing.T) {
	f := newDoctorFixture(t)
	delete(f.env, "CLEARANCE_WAIT_IMAGE")
	cs, _, code := f.run(t)
	doctorWant(t, cs, "wait-image", levelWarn, "CLEARANCE_WAIT_IMAGE")
	if code != 0 {
		t.Errorf("a warning must not fail the run, exit %d", code)
	}
}

func TestDoctorToken(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f *doctorFixture)
		level  string
		text   string
	}{
		{"missing", func(t *testing.T, f *doctorFixture) { os.Remove(f.token) }, levelFail, "does not exist"},
		{"empty", func(t *testing.T, f *doctorFixture) { rewrite(f.token, "\n") }, levelFail, "is empty"},
		{"inner whitespace", func(t *testing.T, f *doctorFixture) { rewrite(f.token, "two words") }, levelFail, "whitespace"},
		{"a directory", func(t *testing.T, f *doctorFixture) { os.Remove(f.token); os.Mkdir(f.token, 0o755) }, levelFail, "not a regular file"},
		{"world readable", func(t *testing.T, f *doctorFixture) { os.Chmod(f.token, 0o644) }, levelWarn, "world-readable"},
		{"private", func(t *testing.T, f *doctorFixture) {}, levelOK, "never printed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			c.mutate(t, f)
			cs, _, code := f.run(t)
			doctorWant(t, cs, "token", c.level, c.text)
			if (c.level == levelFail) != (code == 1) {
				t.Errorf("exit %d for a %s token", code, c.level)
			}
		})
	}
}

func TestDoctorUnreadableToken(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	f := newDoctorFixture(t)
	os.Chmod(f.token, 0o000)
	cs, _, code := f.run(t)
	doctorWant(t, cs, "token", levelFail, "not readable")
	if code != 1 {
		t.Errorf("exit %d", code)
	}
}

func TestDoctorCore(t *testing.T) {
	t.Run("accepted token", func(t *testing.T) {
		f := newDoctorFixture(t)
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "core", levelOK, "reachable")
		doctorWant(t, cs, "core-auth", levelOK, "accepted the token")
	})
	t.Run("rejected token", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.core.want = "some-other-token"
		cs, _, code := f.run(t)
		doctorWant(t, cs, "core-auth", levelFail, "rejected the token")
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("forbidden", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.core.status = http.StatusForbidden
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "core-auth", levelFail, "CLEARANCE_VERIFIERS")
	})
	t.Run("unreachable", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_URL"] = "http://127.0.0.1:1"
		cs, _, code := f.run(t)
		doctorWant(t, cs, "core", levelFail, "not reachable")
		if len(doctorFind(cs, "core-auth")) != 0 {
			t.Errorf("an unreachable core still produced an auth verdict: %+v", doctorFind(cs, "core-auth"))
		}
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("not a core", func(t *testing.T) {
		f := newDoctorFixture(t)
		other := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(other.Close)
		f.env["CLEARANCE_URL"] = other.URL
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "core", levelFail, "not a Clearance core")
	})
	t.Run("no token file means no auth verdict", func(t *testing.T) {
		f := newDoctorFixture(t)
		os.Remove(f.token)
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "core", levelOK, "reachable")
		doctorWant(t, cs, "core-auth", levelFail, "not checked")
	})
	t.Run("plain http to a non-loopback host warns", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_URL"] = "http://clearance.example.test"
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "core-tls", levelWarn, "plain http")
	})
}

func TestDoctorChartRepos(t *testing.T) {
	t.Run("empty fails", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CHART_REPOS"] = ""
		cs, _, code := f.run(t)
		doctorWant(t, cs, "chart-repos", levelFail, "empty")
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("entries are normalised the way the plugin does", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CHART_REPOS"] = "git@GIT.example.test:org/charts.git https://user:pw@charts.example.test/ oci://Registry.example.test/org/charts"
		cs, _, code := f.run(t)
		if code != 0 {
			t.Fatalf("exit %d: %+v", code, cs)
		}
		doctorWant(t, cs, "chart-repos", levelOK, "ssh://git.example.test/org/charts")
		doctorWant(t, cs, "chart-repos", levelOK, "oci://registry.example.test/org/charts")
		for _, c := range doctorFind(cs, "chart-repos") {
			if strings.Contains(c.Msg, "pw") {
				t.Errorf("a password was printed: %s", c.Msg)
			}
		}
	})
	t.Run("a bad entry fails", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CHART_REPOS"] = "https://git.example.test/org/charts file:///etc"
		cs, _, code := f.run(t)
		doctorWant(t, cs, "setting", levelFail, "CLEARANCE_CHART_REPOS entry")
		doctorWant(t, cs, "chart-repos", levelFail, "refuses to start")
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("a duplicate warns", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CHART_REPOS"] = "https://git.example.test/org/charts.git https://GIT.example.test/org/charts/"
		cs, _, code := f.run(t)
		doctorWant(t, cs, "chart-repos", levelWarn, "same repository")
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	})
}

func TestDoctorCache(t *testing.T) {
	t.Run("writable, and the probe file is removed", func(t *testing.T) {
		f := newDoctorFixture(t)
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "cache", levelOK, "writable")
		left, _ := os.ReadDir(f.env["CLEARANCE_CMP_CACHE_DIR"])
		if len(left) != 0 {
			t.Errorf("doctor left %d files in the cache directory", len(left))
		}
	})
	t.Run("not writable", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root writes everywhere")
		}
		f := newDoctorFixture(t)
		ro := filepath.Join(f.dir, "ro")
		os.Mkdir(ro, 0o500)
		f.env["CLEARANCE_CMP_CACHE_DIR"] = filepath.Join(ro, "cache")
		cs, _, code := f.run(t)
		doctorWant(t, cs, "cache", levelFail, "cannot be created")
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	})
}

func TestDoctorTools(t *testing.T) {
	f := newDoctorFixture(t)
	f.tools["kustomize"] = ""
	cs, _, code := f.run(t)
	doctorWant(t, cs, "kustomize", levelFail, "not on PATH")
	doctorWant(t, cs, "git", levelOK, "git version 2.45.0")
	doctorWant(t, cs, "helm", levelOK, "v4.2.1")
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	// only the first line of a tool's output is shown
	for _, c := range doctorFind(cs, "git") {
		if strings.Contains(c.Msg, "second line") {
			t.Errorf("more than the version was printed: %s", c.Msg)
		}
	}
}

func TestDoctorToolVersionCommandFails(t *testing.T) {
	f := newDoctorFixture(t)
	env := DoctorEnv{Get: func(k string) string { return f.env[k] }, LookPath: func(n string) (string, error) { return "/x/" + n, nil },
		Run: func(context.Context, string, ...string) (string, error) { return "", errors.New("exit status 1") }, PluginDir: f.plugin, CmpServer: f.server, Timeout: time.Second}
	cs := Doctor(context.Background(), env)
	doctorWant(t, cs, "helm", levelFail, "did not report a version")
}

func TestDoctorNetns(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		deny  bool
		level string
		text  string
		exit  int
	}{
		{"on", "try", false, levelOK, "on:", 0},
		{"unavailable under try warns", "try", true, levelWarn, "unavailable", 0},
		{"unavailable under require fails", "require", true, levelFail, "CLEARANCE_CMP_NETNS=require", 1},
		{"off", "off", true, levelOK, "off:", 0},
		{"unset is try", "", true, levelWarn, "unavailable", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.env[NetnsEnv] = c.mode
			old := isolate
			t.Cleanup(func() { isolate = old; SetNetns("") })
			isolate = func(*exec.Cmd) (bool, error) {
				if c.deny {
					return false, errors.New("operation not permitted")
				}
				return true, nil
			}
			cs, _, code := f.run(t)
			doctorWant(t, cs, "netns", c.level, c.text)
			if code != c.exit {
				t.Errorf("exit %d, want %d", code, c.exit)
			}
		})
	}
}

func TestDoctorPluginSocket(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		f := newDoctorFixture(t)
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "plugin-socket", levelOK, "exists")
		doctorWant(t, cs, "cmp-server", levelOK, "present")
	})
	t.Run("absent is a warning, as outside the sidecar", func(t *testing.T) {
		f := newDoctorFixture(t)
		os.Remove(f.server)
		os.Remove(f.plugin)
		cs, _, code := f.run(t)
		doctorWant(t, cs, "plugin-socket", levelWarn, "does not exist")
		doctorWant(t, cs, "cmp-server", levelWarn, "copyutil")
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("writes nothing there", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.run(t)
		left, _ := os.ReadDir(f.plugin)
		if len(left) != 0 {
			t.Errorf("doctor wrote %d files in the plugin directory", len(left))
		}
	})
}

func TestDoctorMainFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := doctorMain([]string{"extra"}, &out, &errb); code != 2 {
		t.Errorf("a stray argument exits %d, want 2", code)
	}
	for _, v := range []string{"0", "0s", "-5s"} {
		if code := doctorMain([]string{"--timeout", v}, &out, &errb); code != 2 {
			t.Errorf("--timeout %s exits %d, want 2", v, code)
		}
	}
	if code := doctorMain([]string{"--no-such-flag"}, &out, &errb); code != 2 {
		t.Errorf("a bad flag exits %d, want 2", code)
	}
}

func TestDoctorCaches(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		f := newDoctorFixture(t)
		cs, _, code := f.run(t)
		doctorWant(t, cs, "chart-cache", levelOK, "512 MiB and 32 entries")
		doctorWant(t, cs, "render-cache", levelOK, "up to 15m0s")
		doctorWant(t, cs, "render-cache", levelOK, "cleared-tree cache TTL is 2m0s")
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("volume smaller than the bound warns, and does not fail", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.free = 100 << 20
		cs, _, code := f.run(t)
		doctorWant(t, cs, "chart-cache", levelWarn, "less than the byte bound")
		doctorWant(t, cs, "chart-cache", levelWarn, "sizeLimit")
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("custom bounds", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CMP_CHART_CACHE_MAX_BYTES"] = "1073741824"
		f.env["CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES"] = "4"
		f.env["CLEARANCE_CMP_RENDER_CACHE_TTL"] = "1h"
		f.env["CLEARANCE_CMP_CACHE_TTL"] = "30s"
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "chart-cache", levelOK, "1.0 GiB and 4 entries")
		doctorWant(t, cs, "render-cache", levelOK, "up to 1h0m0s")
		doctorWant(t, cs, "render-cache", levelOK, "TTL is 30s")
	})
	t.Run("zero turns each off", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES"] = "0"
		f.env["CLEARANCE_CMP_RENDER_CACHE_TTL"] = "0"
		cs, _, code := f.run(t)
		doctorWant(t, cs, "chart-cache", levelOK, "off")
		doctorWant(t, cs, "render-cache", levelOK, "off")
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("unknown free space is not a warning", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.free = 0
		cs, _, _ := f.run(t)
		doctorWant(t, cs, "chart-cache", levelOK, "could not be read")
	})
	t.Run("malformed values fail in settings, all at once", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.env["CLEARANCE_CMP_CHART_CACHE_MAX_BYTES"] = "lots"
		f.env["CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES"] = "-1"
		f.env["CLEARANCE_CMP_RENDER_CACHE_TTL"] = "soon"
		cs, _, code := f.run(t)
		for _, s := range []string{"MAX_BYTES", "MAX_ENTRIES", "RENDER_CACHE_TTL"} {
			doctorWant(t, cs, "setting", levelFail, s)
		}
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	})
}

func TestDoctorDoesNotReadATokenFileTheTokenCheckRejected(t *testing.T) {
	f := newDoctorFixture(t)
	f.env["CLEARANCE_TOKEN_FILE"] = "/dev/zero" // a device: reading it would never end
	done := make(chan []Check, 1)
	go func() { cs, _, _ := f.run(t); done <- cs }()
	select {
	case cs := <-done:
		doctorWant(t, cs, "token", levelFail, "not a regular file")
		doctorWant(t, cs, "core-auth", levelFail, "not checked")
	case <-time.After(20 * time.Second):
		t.Fatal("doctor read a rejected token file")
	}
}

// The filesystem sandbox check: on, off (said so), unavailable (a warning in try, a failure in require).
func TestDoctorFSSandbox(t *testing.T) {
	oldP := landlockProbe
	t.Cleanup(func() { landlockProbe = oldP; SetFSSandbox("", "") })
	f := newDoctorFixture(t)
	landlockProbe = func() (int, error) { return 4, nil }
	delete(f.env, FSSandboxEnv)
	cs, _, _ := f.run(t)
	doctorWant(t, cs, "fs-sandbox", levelOK, "token is out of their reach")
	landlockProbe = func() (int, error) { return 0, errors.New("injected: no landlock") }
	cs, _, code := f.run(t)
	doctorWant(t, cs, "fs-sandbox", levelWarn, "injected: no landlock")
	if code != 0 {
		t.Fatal("try without Landlock failed doctor")
	}
	f.env[FSSandboxEnv] = "require"
	cs, _, code = f.run(t)
	doctorWant(t, cs, "fs-sandbox", levelFail, FSSandboxEnv+"=require")
	if code != 1 {
		t.Fatal("require without Landlock passed doctor")
	}
	f.env[FSSandboxEnv] = "on"
	cs, _, _ = f.run(t)
	doctorWant(t, cs, "fs-sandbox", levelFail, FSSandboxEnv)
	doctorWant(t, cs, "setting", levelFail, FSSandboxEnv)
}

// The limits check prints the bounds, and warns when a full set of concurrent renders could pass the container's limit.
func TestDoctorRenderLimits(t *testing.T) {
	if !shimSupported {
		t.Skip("the memory comparison is Linux only")
	}
	f := newDoctorFixture(t)
	f.memMax = strconv.FormatInt(4<<30, 10)
	cs, _, _ := f.run(t)
	doctorWant(t, cs, "render-limits", levelOK, "fits the container's memory limit")
	f.memMax = strconv.FormatInt(512<<20, 10)
	cs, _, code := f.run(t)
	doctorWant(t, cs, "render-limits", levelWarn, EnvMaxRenders)
	if code != 0 {
		t.Fatal("a warning failed doctor")
	}
	f.env[EnvMaxRenders] = "1"
	cs, _, _ = f.run(t)
	doctorWant(t, cs, "render-limits", levelOK, "1 renders at once")
	f.env[EnvMaxMemory], f.env[EnvMaxCPU] = "lots", "never"
	cs, _, code = f.run(t)
	doctorWant(t, cs, "setting", levelFail, EnvMaxMemory)
	doctorWant(t, cs, "setting", levelFail, EnvMaxCPU)
	if code != 1 {
		t.Fatal("bad limits passed doctor")
	}
}
