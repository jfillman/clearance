package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/jfillman/clearance/internal/store"
)

// The flight recorder's fields (AP-C1, AP-C2; A-4): what a run's records say about the model it ran on, the
// Preflight result of its definition, and what it cost. Every one is claimed: the core cannot see the model
// provider's answer or the run's clock, only who reported them.

// MaxTokens caps every token and call count a provider reports (2^40, about a trillion).
const MaxTokens = int64(1) << 40

// ModelCallTool is the decision a model call's outcome belongs to (decide.ActionModelCall's record tool).
const ModelCallTool = "model.call"

// RunRecordKinds are the provider records that may carry model_version and preflight: a run's own records.
// CostKinds may carry cost: the run's summary when it ends.
var (
	RunRecordKinds = []string{"session.open", "run.launch", "run.finish", "run.delete"}
	CostKinds      = []string{"run.finish"}
)

// PreflightResults are a Preflight result's values (schemas/evidence.schema.json preflight.result).
var PreflightResults = []string{"pass", "fail", "not-run"}

// modelVersionRx is a model version as a provider names it: claude-sonnet-5-5-20261015, default/qwen3-8b.
var modelVersionRx = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}\z`)

// definitionRx is an agent definition's name.
var definitionRx = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z`)

// ComputeClasses are the compute classes a definition may name (the agent-definition schema's profile.compute, and
// decide's Limits.Compute): a run's cost names the one its session was granted.
var ComputeClasses = []string{"small", "medium", "large", "gpu"}

// Usage is one model call's token usage as the provider's model proxy metered it: the provider's four kinds of
// token (Anthropic's usage block) and charged_tokens, the call's weighted charge (the gateway's weights: a cache
// read costs a tenth of an input token). The session's model_tokens budget counts that charge up to its limit, and a
// call that overruns it trips the session's breaker: the record keeps what the call cost, the budget what it allowed.
// Only on a model.call outcome.
type Usage struct {
	InputTokens              int64  `json:"input_tokens,omitempty"`
	OutputTokens             int64  `json:"output_tokens,omitempty"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens,omitempty"`
	ChargedTokens            *int64 `json:"charged_tokens" contract:"required"`
}

// Preflight is the Preflight result of the run's definition (A-6 scores it; not-run until a result exists).
type Preflight struct {
	Result     string `json:"result" contract:"required"`
	Definition string `json:"definition,omitempty"`
	Cases      *int64 `json:"cases,omitempty"`
}

// Cost is a run's own summary when it ends (run.finish): the session's model usage summed over its calls, its
// model and tool calls, how long it ran and the compute class it ran on. The counts API sums model.call outcomes
// for tokens, not this, so a run is never counted twice; this is the run's view of the same numbers.
type Cost struct {
	ChargedTokens            *int64 `json:"charged_tokens" contract:"required"`
	InputTokens              int64  `json:"input_tokens,omitempty"`
	OutputTokens             int64  `json:"output_tokens,omitempty"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens,omitempty"`
	ModelCalls               int64  `json:"model_calls,omitempty"`
	ToolCalls                int64  `json:"tool_calls,omitempty"`
	WallSeconds              int64  `json:"wall_seconds,omitempty"`
	Compute                  string `json:"compute,omitempty"`
}

func jsonInt(v int64) json.Number { return json.Number(strconv.FormatInt(v, 10)) }

func counted(name string, v int64) error {
	if v < 0 || v > MaxTokens {
		return fmt.Errorf("%s is an integer from 0 to %d", name, MaxTokens)
	}
	return nil
}

// field is the record's value of a usage: every kind present, so a reader sums without a missing key.
func (u *Usage) field() (map[string]any, error) {
	if u.ChargedTokens == nil {
		return nil, errors.New("usage.charged_tokens is required")
	}
	for _, c := range []struct {
		k string
		v int64
	}{{"input_tokens", u.InputTokens}, {"output_tokens", u.OutputTokens},
		{"cache_creation_input_tokens", u.CacheCreationInputTokens}, {"cache_read_input_tokens", u.CacheReadInputTokens},
		{"charged_tokens", *u.ChargedTokens}} {
		if err := counted("usage."+c.k, c.v); err != nil {
			return nil, err
		}
	}
	return map[string]any{"input_tokens": jsonInt(u.InputTokens), "output_tokens": jsonInt(u.OutputTokens),
		"cache_creation_input_tokens": jsonInt(u.CacheCreationInputTokens),
		"cache_read_input_tokens":     jsonInt(u.CacheReadInputTokens), "charged_tokens": jsonInt(*u.ChargedTokens)}, nil
}

func (p *Preflight) field() (map[string]any, error) {
	if !slices.Contains(PreflightResults, p.Result) {
		return nil, fmt.Errorf("preflight.result is one of %v", PreflightResults)
	}
	out := map[string]any{"result": p.Result}
	if p.Definition != "" {
		if !definitionRx.MatchString(p.Definition) {
			return nil, errors.New("preflight.definition is an agent definition's name")
		}
		out["definition"] = p.Definition
	}
	if p.Cases != nil {
		if *p.Cases < 0 || *p.Cases > 10000 {
			return nil, errors.New("preflight.cases is an integer from 0 to 10000")
		}
		out["cases"] = jsonInt(*p.Cases)
	}
	return out, nil
}

func (c *Cost) field() (map[string]any, error) {
	if c.ChargedTokens == nil {
		return nil, errors.New("cost.charged_tokens is required")
	}
	out := map[string]any{}
	for _, f := range []struct {
		k string
		v int64
	}{{"charged_tokens", *c.ChargedTokens}, {"input_tokens", c.InputTokens}, {"output_tokens", c.OutputTokens},
		{"cache_creation_input_tokens", c.CacheCreationInputTokens}, {"cache_read_input_tokens", c.CacheReadInputTokens},
		{"model_calls", c.ModelCalls}, {"tool_calls", c.ToolCalls}, {"wall_seconds", c.WallSeconds}} {
		if err := counted("cost."+f.k, f.v); err != nil {
			return nil, err
		}
		out[f.k] = jsonInt(f.v)
	}
	if c.Compute != "" {
		if !slices.Contains(ComputeClasses, c.Compute) {
			return nil, fmt.Errorf("cost.compute is a compute class (one of %v)", ComputeClasses)
		}
		out["compute"] = c.Compute
	}
	return out, nil
}

func modelVersion(v string) error {
	if !modelVersionRx.MatchString(v) {
		return errors.New("model_version is a model's name as its provider gives it (at most 200 characters)")
	}
	return nil
}

// recorderFields adds a provider record's flight-recorder fields to ev, refusing them on a kind that does not take
// them.
func (e *ProviderEvent) recorderFields(kind string, ev store.Event) error {
	if e.ModelVersion != nil {
		if !slices.Contains(RunRecordKinds, kind) {
			return fmt.Errorf("model_version is set on a run's records only (%v)", RunRecordKinds)
		}
		if err := modelVersion(*e.ModelVersion); err != nil {
			return err
		}
		ev["model_version"] = *e.ModelVersion
	}
	if e.Preflight != nil {
		if !slices.Contains(RunRecordKinds, kind) {
			return fmt.Errorf("preflight is set on a run's records only (%v)", RunRecordKinds)
		}
		p, err := e.Preflight.field()
		if err != nil {
			return err
		}
		ev["preflight"] = p
	}
	if e.Cost != nil {
		if !slices.Contains(CostKinds, kind) {
			return fmt.Errorf("cost is set on %v records only", CostKinds)
		}
		c, err := e.Cost.field()
		if err != nil {
			return err
		}
		ev["cost"] = c
	}
	return nil
}
