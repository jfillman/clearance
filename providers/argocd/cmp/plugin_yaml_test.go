package main

import (
	"os"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func readPluginYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

// The default plugin is addressed as `clearance` (no version) and the canary file as `clearance-canary`; the two must
// differ in nothing else, or a canary would test something other than the release.
func TestPluginNamesAndCanaryParity(t *testing.T) {
	def := readPluginYAML(t, "plugin.yaml")
	can := readPluginYAML(t, "plugin-canary.yaml")
	dspec, cspec := def["spec"].(map[string]any), can["spec"].(map[string]any)
	if def["metadata"].(map[string]any)["name"] != "clearance" || dspec["version"] != nil {
		t.Fatalf("plugin.yaml must be name clearance with no version, got %v / %v", def["metadata"], dspec["version"])
	}
	if can["metadata"].(map[string]any)["name"] != "clearance" || cspec["version"] != "canary" {
		t.Fatalf("plugin-canary.yaml must be name clearance, version canary, got %v / %v", can["metadata"], cspec["version"])
	}
	delete(cspec, "version")
	if !reflect.DeepEqual(dspec, cspec) {
		t.Fatalf("the canary plugin differs from the default beyond its version:\n%v\n%v", dspec, cspec)
	}
}
