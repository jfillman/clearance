package gate

import (
	"context"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/token"
)

// What the subscriber-side packet routes (P-1: publishing a packet, granting a recipient access) take from the gate:
// who the subscriber is, and the key and issuer their credentials are signed under. The routes themselves, and the
// records they write, are the server's (internal/server/assurance.go).

// Subscriber is the person who granted something: an admin (CLEARANCE_ADMINS), signed in themselves or named by a
// delegate.
type Subscriber struct {
	Person string
	// Via is the delegate that named the person, when one did.
	Via *string
	// Sub and Iss are the identity the record names as the initiator (the person's IdP subject and issuer; a delegate
	// is named in Iss).
	Sub, Iss string
}

// Subscriber is the person behind p when they are an admin; otherwise an *Error (DG-PACKET-ADMIN 403, DG-DELEGATE,
// DG-PERSON). A packet is the subscriber's own evidence: publishing one and opening it to a recipient is the
// subscriber's act, so it needs the same standing as breaking glass.
func (s *Service) Subscriber(ctx context.Context, p authn.Principal, onBehalfOf string) (Subscriber, error) {
	person, via, who, err := s.admin(ctx, p, onBehalfOf, "DG-PACKET-ADMIN",
		"Only an admin, or a delegate naming one, may publish a packet or grant a recipient access to it.")
	if err != nil {
		return Subscriber{}, err
	}
	return Subscriber{Person: person, Via: via, Sub: who.sub, Iss: who.iss}, nil
}

// Credentials is the signer and issuer packet access credentials are signed under: the clearance token's, so there is
// one key, one rotation and one key set (GET /v1/keys). An *Error (DG-NO-SIGNER 503) when the core has no signing key.
func (s *Service) Credentials() (token.Signer, string, error) {
	if s.Tokens == nil || s.Tokens.Signer == nil {
		return nil, "", gerr("DG-NO-SIGNER", "this core has no signing key (CLEARANCE_SIGNING_KEY_FILE), so it cannot issue a packet credential",
			"Configure the token signing key.", 503)
	}
	return s.Tokens.Signer, s.Tokens.issuer(), nil
}
