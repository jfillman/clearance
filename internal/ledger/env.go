package ledger

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// FromEnv reads the ledger's configuration from getenv, or nil when CLEARANCE_LEDGER_DIR is unset: the ledger is
// off unless configured, and a release that adds it changes nothing in a running deployment.
//
//	CLEARANCE_LEDGER_DIR                  the Tessera volume (a mounted, writable, single-writer directory). Setting it
//	                                      turns the ledger on; the three below are then required
//	CLEARANCE_LEDGER_KEY_FILE             the log's signing key: a signed-note Ed25519 secret key, read from the file
//	CLEARANCE_LEDGER_WITNESS_POLICY_FILE  the witness policy (witness lines with the witness's cosignature vkey and
//	                                      URL, a group line per quorum, a quorum line); at least one witness
//	CLEARANCE_LEDGER_RETIRED_KEYS_FILE    vkeys of the log's retired signing keys, one per line (default none)
//	CLEARANCE_LEDGER_CHECKPOINT_INTERVAL  a Go duration, 1s to 1h (default 1m): how often a grown log is checkpointed
//	                                      and the witnesses are asked
//	CLEARANCE_LEDGER_TIER3_WAIT           true (default) | false: a tier 3 change waits while evidence cannot be
//	                                      checkpointed
//	CLEARANCE_LEDGER_STALL_AFTER          a Go duration: how long records may wait for a witnessed checkpoint before the
//	                                      ledger counts as stalled (default three intervals plus the witness timeout)
func FromEnv(getenv func(string) string) (*Config, error) {
	dir := getenv("CLEARANCE_LEDGER_DIR")
	if dir == "" {
		for _, k := range []string{"CLEARANCE_LEDGER_KEY_FILE", "CLEARANCE_LEDGER_WITNESS_POLICY_FILE", "CLEARANCE_LEDGER_RETIRED_KEYS_FILE",
			"CLEARANCE_LEDGER_CHECKPOINT_INTERVAL", "CLEARANCE_LEDGER_TIER3_WAIT", "CLEARANCE_LEDGER_STALL_AFTER"} {
			if getenv(k) != "" {
				return nil, fmt.Errorf("%s is set but CLEARANCE_LEDGER_DIR is not: the ledger is off without its volume", k)
			}
		}
		return nil, nil
	}
	keyFile, policyFile := getenv("CLEARANCE_LEDGER_KEY_FILE"), getenv("CLEARANCE_LEDGER_WITNESS_POLICY_FILE")
	if keyFile == "" || policyFile == "" {
		return nil, errors.New("CLEARANCE_LEDGER_DIR needs CLEARANCE_LEDGER_KEY_FILE and CLEARANCE_LEDGER_WITNESS_POLICY_FILE")
	}
	key, err := LoadLogKey(keyFile, getenv("CLEARANCE_LEDGER_RETIRED_KEYS_FILE"))
	if err != nil {
		return nil, err
	}
	policy, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, fmt.Errorf("CLEARANCE_LEDGER_WITNESS_POLICY_FILE: %w", err)
	}
	cfg := &Config{Log: LogConfig{Dir: dir, Key: key, Policy: policy}, Tier3Wait: true}
	if v := getenv("CLEARANCE_LEDGER_CHECKPOINT_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second || d > time.Hour {
			return nil, fmt.Errorf("CLEARANCE_LEDGER_CHECKPOINT_INTERVAL: %q is not a Go duration from 1s to 1h", v)
		}
		cfg.Log.CheckpointInterval = d
	}
	if v := getenv("CLEARANCE_LEDGER_STALL_AFTER"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second {
			return nil, fmt.Errorf("CLEARANCE_LEDGER_STALL_AFTER: %q is not a Go duration of at least 1s", v)
		}
		cfg.StallAfter = d
	}
	switch strings.ToLower(getenv("CLEARANCE_LEDGER_TIER3_WAIT")) {
	case "", "true":
	case "false":
		cfg.Tier3Wait = false
	default:
		return nil, errors.New("CLEARANCE_LEDGER_TIER3_WAIT is true or false")
	}
	return cfg, nil
}
