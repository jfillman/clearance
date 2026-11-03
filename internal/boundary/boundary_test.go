// Package boundary checks what the Clearance core is not (the boundary rule, R-3 and R-5). Clearance decides and
// records; the AI gateway (Autopilot) enforces. So the core holds no session store, no MCP server and no tool
// dispatch, imports no MCP or model-provider SDK, and carries no Hangar vocabulary: Hangar's policy is a bundle a
// deployment loads (CLEARANCE_BUNDLES) and its names are configuration (internal/vocab, CLEARANCE_ENV_*).
//
// The core is the module's non-test Go source under internal/, cmd/ and client/, its embedded data files, and the
// Python client it publishes (clients/python/src). Comments are not code or data: they may say where a port came
// from. Tests and the test-support packages (a directory ending in "test": decidetest, vocabtest, deftest,
// storetest) hold the lab deployment's values, which is what they test against.
package boundary

import (
	"bufio"
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const root = "../.."

var coreDirs = []string{"internal", "cmd", "client"}

// ---- what the core contains ---------------------------------------------------------------------------------------

type tok struct {
	line int
	kind token.Token
	text string // a literal's value (unquoted) or an identifier
}

// goTokens is every identifier and string or char literal in Go source, comments skipped.
func goTokens(name string, src []byte) ([]tok, error) {
	fs := token.NewFileSet()
	f := fs.AddFile(name, -1, len(src))
	var s scanner.Scanner
	var errs []string
	s.Init(f, src, func(pos token.Position, msg string) { errs = append(errs, pos.String()+": "+msg) }, 0)
	var out []tok
	for {
		pos, t, lit := s.Scan()
		if t == token.EOF {
			break
		}
		switch t {
		case token.IDENT:
			out = append(out, tok{fs.Position(pos).Line, t, lit})
		case token.STRING, token.CHAR:
			v, err := strconv.Unquote(lit)
			if err != nil {
				v = lit
			}
			out = append(out, tok{fs.Position(pos).Line, t, v})
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

func isTestSupport(rel string) bool {
	if strings.HasSuffix(rel, "_test.go") {
		return true
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts[:len(parts)-1] {
		if strings.HasSuffix(p, "test") || p == "testdata" {
			return true
		}
	}
	return false
}

// coreFiles is every non-test file under the core's directories, by path relative to the module root.
func coreFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, d := range coreDirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if !isTestSupport(rel) {
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func read(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tokens(t *testing.T, rel string) []tok {
	t.Helper()
	ts, err := goTokens(rel, read(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// ---- no Hangar vocabulary (R-5) -----------------------------------------------------------------------------------

var hangarNames = regexp.MustCompile(`(?i)hangar|glidepath|airframe|autopilot|skyport|apron|people-dex|riley-roooo|` +
	`gitops-|check-ride|\btower\b|\bflight\b`)

// file -> why it may still name Hangar. Each entry is a recorded exception, not a place to add more.
var hangarDataExceptions = map[string]string{
	"internal/profile/agent-definition.schema.json": "Autopilot's agent-definition schema (profile.glidepath/airframe, " +
		"glidepath event sources), embedded byte for byte so the gate can tier a definition change; reading it from " +
		"configuration is the follow-up to R-5",
}

func TestTheCoreContainsNoHangarNames(t *testing.T) {
	var found []string
	for _, rel := range coreFiles(t) {
		if _, ok := hangarDataExceptions[rel]; ok {
			continue
		}
		switch filepath.Ext(rel) {
		case ".go":
			for _, k := range tokens(t, rel) {
				if hangarNames.MatchString(k.text) {
					found = append(found, fmt.Sprintf("%s:%d: %.80q", rel, k.line, k.text))
				}
			}
		case ".json", ".yaml", ".yml", ".sql":
			for i, l := range lines(read(t, rel)) {
				if hangarNames.MatchString(l) {
					found = append(found, fmt.Sprintf("%s:%d: %.80s", rel, i+1, strings.TrimSpace(l)))
				}
			}
		}
	}
	err := filepath.WalkDir(filepath.Join(root, "clients", "python", "src"), func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() || filepath.Ext(p) != ".py" {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for i, l := range lines(read(t, rel)) {
			if hangarNames.MatchString(l) {
				found = append(found, fmt.Sprintf("%s:%d: %.80s", rel, i+1, strings.TrimSpace(l)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Errorf("the core names Hangar (make it configuration or a bundle):\n%s", strings.Join(found, "\n"))
	}
}

// A check that matches nothing proves nothing: it finds a Hangar name in a literal, not in a comment, and it sees
// the whole core.
func TestTheHangarNamesCheckSeesWhatItShould(t *testing.T) {
	ts, err := goTokens("x.go", []byte("// glidepath in a comment\n/* airframe */ x := \"a glidepath.runs.list call\" + `airframe`\n"))
	if err != nil {
		t.Fatal(err)
	}
	var hit []string
	for _, k := range ts {
		if hangarNames.MatchString(k.text) {
			hit = append(hit, k.text)
		}
	}
	if strings.Join(hit, "|") != "a glidepath.runs.list call|airframe" {
		t.Errorf("hits %q", hit)
	}
	n := 0
	for _, rel := range coreFiles(t) {
		if strings.HasSuffix(rel, ".go") {
			n++
		}
	}
	if n <= 100 {
		t.Errorf("only %d core Go files", n)
	}
	for f := range hangarDataExceptions {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Errorf("%s is gone: drop its exception", f)
		}
	}
}

// ---- no session store, MCP server or tool dispatch (R-3) ----------------------------------------------------------

// An MCP SDK or a model provider's SDK in the core's dependencies means it serves agents or proxies models: the
// gateway's work.
var gatewayModules = regexp.MustCompile(`(?i)modelcontextprotocol|mcp-go|mark3labs|metoro-io/mcp|` +
	`(^|/)mcp($|[/-])|anthropic|openai|langchain|bedrockruntime|generativelanguage`)

// A package of the core named for one of the gateway's parts (the modules R-3 moved to Autopilot).
var gatewayPackages = map[string]bool{"session": true, "sessions": true, "dispatch": true, "dispatcher": true,
	"mcp": true, "mcpserver": true, "modelproxy": true, "inbox": true, "runtimes": true, "limits": true,
	"control": true, "results": true, "artifacts": true, "toolregistry": true, "registry": true, "backends": true,
	"trigger": true, "triggers": true, "scheduler": true}

// An identifier the core declares or uses for one of them. SessionState (a session as the gateway reports it in a
// decision request) and the action names session.open and session.spawn are decision vocabulary and stay.
var gatewayIdents = regexp.MustCompile(`(?i)sessionstore|dispatch|mcp|toolregistry|modelproxy|runtree|inbox|` +
	`humanrequest|toolhandler|backendregistry`)

// Literals that would put the core on the agents' side of the line: the MCP endpoint, an MCP method, the model
// proxy's routes.
var gatewayLiterals = regexp.MustCompile(`^/mcp(/|$)|^(tools/(list|call)|initialize|notifications/[a-z_]+)$|` +
	`^/v1/messages(/|$)|^/v1/chat/completions$`)

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if e, ok := err.(*exec.ExitError); ok {
			stderr = string(e.Stderr)
		}
		t.Fatalf("go list %v: %v %s", args, err, stderr)
	}
	return strings.Fields(string(out))
}

func TestTheCoreImportsNoMCPOrModelSDK(t *testing.T) {
	deps := goList(t, "-deps", "-f", "{{.ImportPath}}", "./cmd/...", "./internal/...", "./client/...")
	if len(deps) < 50 {
		t.Fatalf("go list -deps saw %d packages", len(deps))
	}
	var bad []string
	for _, d := range deps {
		if gatewayModules.MatchString(d) {
			bad = append(bad, d)
		}
	}
	for _, l := range lines(read(t, "go.mod")) {
		if f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "require ")); len(f) >= 2 &&
			strings.Contains(f[0], ".") && gatewayModules.MatchString(f[0]) {
			bad = append(bad, "go.mod: "+f[0])
		}
	}
	if len(bad) > 0 {
		t.Errorf("the core depends on an MCP or model SDK (the gateway's, not the core's):\n%s", strings.Join(bad, "\n"))
	}
}

func TestTheCoreHasNoGatewayPackages(t *testing.T) {
	pkgs := goList(t, "-f", "{{.ImportPath}}", "./...")
	if len(pkgs) < 20 {
		t.Fatalf("go list saw %d packages", len(pkgs))
	}
	for _, p := range pkgs {
		if gatewayPackages[p[strings.LastIndex(p, "/")+1:]] {
			t.Errorf("%s: a package named for a gateway part (sessions, MCP, dispatch, model proxy, inbox, runtimes, triggers)", p)
		}
	}
}

func TestTheCoreHasNoSessionStoreMCPOrDispatchCode(t *testing.T) {
	var found []string
	for _, rel := range coreFiles(t) {
		if filepath.Ext(rel) != ".go" {
			continue
		}
		for _, k := range tokens(t, rel) {
			if (k.kind == token.IDENT && gatewayIdents.MatchString(k.text)) ||
				(k.kind == token.STRING && gatewayLiterals.MatchString(k.text)) {
				found = append(found, fmt.Sprintf("%s:%d: %.80q", rel, k.line, k.text))
			}
		}
	}
	if len(found) > 0 {
		t.Errorf("the core holds gateway code (a session store, an MCP surface, tool dispatch, a model proxy):\n%s",
			strings.Join(found, "\n"))
	}
}

// The gateway checks match what they should and not the decision vocabulary that stays.
func TestTheGatewayChecksSeeWhatTheyShould(t *testing.T) {
	src := "// a SessionStore in a comment\ntype SessionStore struct{}\nfunc Dispatch() {}\nvar mcpServer = 1\n" +
		"var r = \"/mcp\"\nvar m = `tools/call`\ntype SessionState struct{}\nconst a = \"session.open\"\nvar s = \"/v1/messages\"\n"
	ts, err := goTokens("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var hit []string
	for _, k := range ts {
		if (k.kind == token.IDENT && gatewayIdents.MatchString(k.text)) ||
			(k.kind == token.STRING && gatewayLiterals.MatchString(k.text)) {
			hit = append(hit, k.text)
		}
	}
	if want := "SessionStore|Dispatch|mcpServer|/mcp|tools/call|/v1/messages"; strings.Join(hit, "|") != want {
		t.Errorf("hits %q, want %s", hit, want)
	}
	for _, m := range []string{"github.com/modelcontextprotocol/go-sdk/mcp", "github.com/mark3labs/mcp-go/server",
		"github.com/anthropics/anthropic-sdk-go", "github.com/openai/openai-go"} {
		if !gatewayModules.MatchString(m) {
			t.Errorf("%s not matched", m)
		}
	}
	for _, m := range []string{"github.com/google/cel-go/cel", "github.com/jackc/pgx/v5", "net/http"} {
		if gatewayModules.MatchString(m) {
			t.Errorf("%s matched", m)
		}
	}
}
