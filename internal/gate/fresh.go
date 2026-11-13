package gate

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/authn"
)

// Freshness (G3) and the surface a person wrote from (G4).
//
// Freshness: a person's write is refused when the sign-in behind it is older than the deployment allows for that
// action. The sign-in time is the ID token's auth_time (when the IdP says the person authenticated), else its iat,
// both verified by the authenticator (authn.ClaimAuthTime). It is evaluated by the core from the token it verified,
// not by a client, so it holds from every surface: the CLI, Tower, Slack. Off (zero) is the product default.

// Freshness is the maximum age of a person's sign-in per action class (CLEARANCE_FRESH_AUTH_*). Zero is no
// requirement.
type Freshness struct {
	// Tier2 applies to clearing a tier 2 change.
	Tier2 time.Duration `json:"tier2"`
	// Tier3Breakglass applies to clearing a tier 3 change and to opening or closing break-glass. When it is zero a
	// tier 3 clear falls back to Tier2 (a higher tier is never less strict than a lower one); break-glass has none.
	Tier3Breakglass time.Duration `json:"tier3Breakglass"`
	// Delegates is what a delegate-named person's write needs: "" or "exempt" (the default: a delegate cannot prove
	// the person's sign-in time, so the rule applies to direct person tokens only) or "require" (the delegate must
	// forward the person's sign-in time in the X-Clearance-Auth-Time header, unix seconds, and it is checked against
	// the same maximum; trusted exactly as far as the delegate is, which already names the person).
	Delegates string `json:"delegates"`
}

// Delegate modes of Freshness.Delegates.
const (
	FreshDelegatesExempt  = "exempt"
	FreshDelegatesRequire = "require"
)

// MinFreshAge and MaxFreshAge bound a configured maximum age.
const (
	MinFreshAge = time.Minute
	MaxFreshAge = 24 * time.Hour
)

// RuleAuthNotFresh is the refusal's rule: 401, with max_age (the limit) and age (the sign-in's) in the body.
const RuleAuthNotFresh = "DG-AUTH-NOT-FRESH"

// Action classes a freshness limit applies to.
const (
	actClearTier2 = iota + 1
	actClearTier3
	actBreakglass
)

func (f Freshness) max(act int) time.Duration {
	switch act {
	case actClearTier2:
		return f.Tier2
	case actClearTier3:
		if f.Tier3Breakglass > 0 {
			return f.Tier3Breakglass
		}
		return f.Tier2
	case actBreakglass:
		return f.Tier3Breakglass
	}
	return 0
}

// clearAction is the action class of clearing a change of this tier (0 for tiers with no class).
func clearAction(tier int) int {
	switch {
	case tier >= 3:
		return actClearTier3
	case tier == 2:
		return actClearTier2
	}
	return 0
}

// FreshAuthError is the refusal for a sign-in that is too old.
type FreshAuthError struct {
	MaxAge, Age time.Duration
	// Missing is a write that carried no sign-in time while the deployment requires one: a delegate-named write with no
	// X-Clearance-Auth-Time (Delegate), or a person token with neither auth_time nor iat.
	Missing, Delegate bool
}

func (e *FreshAuthError) Error() string {
	if e.Missing && e.Delegate {
		return "this action needs the person's sign-in time (X-Clearance-Auth-Time) and none was sent"
	}
	if e.Missing {
		return "this action needs a recent sign-in and the token carries no sign-in time (auth_time or iat)"
	}
	return fmt.Sprintf("your sign-in is %s old; this action needs one at most %s old", e.Age.Round(time.Second), e.MaxAge)
}

// checkFresh refuses the write when its sign-in is older than the limit of the action (nil: allowed). A direct
// person token is checked against its verified auth_time or iat; a delegate-named write against the forwarded
// sign-in time when Delegates is "require", and not at all otherwise. A person token with no usable sign-in time
// (an authenticator that does not say, `core --insecure-dev-auth`) fails closed when a limit is set.
func (s *Service) checkFresh(ctx context.Context, p authn.Principal, onBehalfOf string, act int) error {
	max := s.Config.Fresh.max(act)
	if max <= 0 {
		return nil
	}
	now := s.Clock()
	var at time.Time
	switch {
	case onBehalfOf != "":
		if s.Config.Fresh.Delegates != FreshDelegatesRequire {
			return nil
		}
		m := metaFrom(ctx)
		if m.AuthTime == nil {
			return &FreshAuthError{MaxAge: max, Missing: true, Delegate: true}
		}
		at = *m.AuthTime
	default:
		sec, ok := p.Claims[authn.ClaimAuthTime].(int64)
		if !ok {
			return &FreshAuthError{MaxAge: max, Missing: true}
		}
		at = time.Unix(sec, 0)
	}
	age := now.Sub(at)
	// A sign-in time in the future (beyond the verifiers' leeway) is not a fresh one.
	if age < -authn.DefaultLeeway || age > max {
		return &FreshAuthError{MaxAge: max, Age: age}
	}
	return nil
}

// CallMeta is what a person's write says about itself beside the body: the surface it came from (claimed, never
// verified) and, from a delegate, the person's sign-in time.
type CallMeta struct {
	// Via is cli, web, slack, api or a name from CLEARANCE_VIAS_EXTRA; SurfaceRef is a bounded reference to where it came from (a Slack
	// permalink). Both are claimed: the caller says them and the core records them as said.
	Via, SurfaceRef string
	// Reason is the person's optional note on a clear (the body's reason), recorded on deploy.clear as they said it.
	Reason string
	// AuthTime is the sign-in time a delegate forwarded (X-Clearance-Auth-Time).
	AuthTime *time.Time
}

// Vias are the surfaces a write may claim out of the box; CLEARANCE_VIAS_EXTRA (Config.ExtraVias) adds a deployment's
// own, such as the name of its portal.
var Vias = []string{"cli", "web", "slack", "api"}

// ViaName is what an extra surface name looks like: a short lowercase word.
var ViaName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// MaxSurfaceRef bounds surface_ref, in bytes.
const MaxSurfaceRef = 512

// The headers a person's write carries them in.
const (
	HeaderVia        = "X-Clearance-Via"
	HeaderSurfaceRef = "X-Clearance-Surface-Ref"
	HeaderAuthTime   = "X-Clearance-Auth-Time"
)

type metaKey struct{}

func metaFrom(ctx context.Context) CallMeta {
	m, _ := ctx.Value(metaKey{}).(CallMeta)
	return m
}

// WithCallMeta returns ctx carrying m.
func WithCallMeta(ctx context.Context, m CallMeta) context.Context {
	return context.WithValue(ctx, metaKey{}, m)
}

// ParseCallMeta reads and validates the headers (*Error 400: DG-VIA, DG-SURFACE-REF, DG-AUTH-TIME); extra are the
// deployment's own surface names beside Vias.
func ParseCallMeta(h http.Header, extra ...string) (CallMeta, error) {
	var m CallMeta
	m.Via = strings.TrimSpace(h.Get(HeaderVia))
	m.SurfaceRef = h.Get(HeaderSurfaceRef)
	if m.Via != "" {
		all := append(slices.Clone(Vias), extra...)
		if !slices.Contains(all, m.Via) {
			return m, gerr("DG-VIA", HeaderVia+" is one of "+strings.Join(all, ", "), "", 400)
		}
	}
	if m.SurfaceRef != "" {
		if m.Via == "" {
			return m, gerr("DG-SURFACE-REF", HeaderSurfaceRef+" needs "+HeaderVia, "", 400)
		}
		if len(m.SurfaceRef) > MaxSurfaceRef || !utf8.ValidString(m.SurfaceRef) || strings.ContainsFunc(m.SurfaceRef, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return m, gerr("DG-SURFACE-REF", fmt.Sprintf("%s is printable text of at most %d bytes", HeaderSurfaceRef, MaxSurfaceRef), "", 400)
		}
	}
	if raw := h.Get(HeaderAuthTime); raw != "" {
		sec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || sec <= 0 {
			return m, gerr("DG-AUTH-TIME", HeaderAuthTime+" is unix seconds", "", 400)
		}
		t := time.Unix(sec, 0)
		m.AuthTime = &t
	}
	return m, nil
}

// surfaceField is the record's claimed `surface` {via, ref} for the call on ctx, or nil when it said none.
func surfaceField(ctx context.Context) map[string]any {
	m := metaFrom(ctx)
	if m.Via == "" {
		return nil
	}
	out := map[string]any{"via": m.Via}
	if m.SurfaceRef != "" {
		out["ref"] = m.SurfaceRef
	}
	return out
}

// withSurface sets ev's surface from ctx when the call claimed one.
func withSurface(ctx context.Context, ev map[string]any) {
	if f := surfaceField(ctx); f != nil {
		ev["surface"] = f
	}
}
