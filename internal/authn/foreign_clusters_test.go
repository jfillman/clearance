package authn

import (
	"strings"
	"testing"
)

const (
	issA = "https://a.example.com/oidc"
	issB = "https://b.example.com/oidc"
)

const twoClusters = `[
 {"cluster":"eks-a","issuer":"https://a.example.com/oidc/","serviceAccounts":["clearance-system/clearance-argocd-agent"]},
 {"cluster":"eks-b","issuer":"https://b.example.com/oidc","serviceAccounts":["argocd-apps/argocd-apps-repo-server"],"jwksURL":"https://b.example.com/keys"}]`

// Several foreign clusters: each authenticates only its own service accounts, as <cluster>/<namespace>/<sa>.
func TestSeveralForeignClustersEachAuthenticateTheirOwn(t *testing.T) {
	ka, kb := keys(t)
	a, err := FromEnv(env(map[string]string{
		"CLEARANCE_FOREIGN_CLUSTERS": twoClusters,
		// the single form keeps working beside the list
		"CLEARANCE_FOREIGN_ISSUER": "https://tower.example.com/oidc", "CLEARANCE_FOREIGN_CLUSTER": "eks-man",
		"CLEARANCE_FOREIGN_SERVICE_ACCOUNTS": "backstage/backstage",
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := a.(*CachingAuthenticator).Inner.(*RoutingAuthenticator)
	if len(r.ByIssuer) != 3 {
		t.Fatalf("issuers %d", len(r.ByIssuer))
	}
	fa, fb := r.ByIssuer[issA].(*ForeignWorkloadAuthenticator), r.ByIssuer[issB].(*ForeignWorkloadAuthenticator)
	if fa.Name != "eks-a" || fa.Keys.URL != issA+"/jwks.json" || fb.Name != "eks-b" || fb.Keys.URL != "https://b.example.com/keys" {
		t.Fatalf("a %+v b %+v", fa, fb)
	}
	fa.Keys = staticJWKS(nil, jwksDoc(jwkOf(&ka.PublicKey, "k1")))
	fb.Keys = staticJWKS(nil, jwksDoc(jwkOf(&kb.PublicKey, "k1")))
	tok := func(iss, sub string, signer any) string {
		return idToken(t, signer, "k1", map[string]any{"iss": iss, "sub": sub, "email": nil, "email_verified": nil})
	}
	p, err := r.Authenticate(bg, tok(issA, "system:serviceaccount:clearance-system:clearance-argocd-agent", ka))
	if err != nil || p.ID != "eks-a/clearance-system/clearance-argocd-agent" || p.Kind != KindForeignWorkload {
		t.Fatalf("a: %+v %v", p, err)
	}
	p, err = r.Authenticate(bg, tok(issB, "system:serviceaccount:argocd-apps:argocd-apps-repo-server", kb))
	if err != nil || p.ID != "eks-b/argocd-apps/argocd-apps-repo-server" {
		t.Fatalf("b: %+v %v", p, err)
	}
	// An SA that cluster A allows, presented with cluster B's issuer (and B's key): refused.
	_, err = r.Authenticate(bg, tok(issB, "system:serviceaccount:clearance-system:clearance-argocd-agent", kb))
	mustRefuse(t, err, "may not call")
	// ...and the reverse.
	_, err = r.Authenticate(bg, tok(issA, "system:serviceaccount:argocd-apps:argocd-apps-repo-server", ka))
	mustRefuse(t, err, "may not call")
	// B's SA signed by A's key under B's issuer: the signature is refused.
	_, err = r.Authenticate(bg, tok(issB, "system:serviceaccount:argocd-apps:argocd-apps-repo-server", ka))
	if err == nil {
		t.Fatal("a token signed by another cluster's key was accepted")
	}
	// An unlisted issuer falls to the workload verifier (TokenReview), which refuses it here.
	_, err = r.Authenticate(bg, tok("https://c.example.com/oidc", "system:serviceaccount:clearance-system:clearance-argocd-agent", ka))
	if err == nil {
		t.Fatal("a token from an unlisted issuer was accepted")
	}
}

func TestForeignClustersRefusedAtStart(t *testing.T) {
	one := func(c, i, sa string) string {
		return `{"cluster":"` + c + `","issuer":"` + i + `","serviceAccounts":[` + sa + `]}`
	}
	ok := `"ns/sa"`
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"same issuer twice":  {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", issA, ok) + "," + one("b", issA+"/", ok) + "]"}, "already named"},
		"same cluster twice": {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", issA, ok) + "," + one("a", issB, ok) + "]"}, "cluster name"},
		"missing cluster":    {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("", issA, ok) + "]"}, "needs cluster, issuer and serviceAccounts"},
		"missing issuer":     {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", "", ok) + "]"}, "needs cluster, issuer and serviceAccounts"},
		"missing accounts":   {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", issA, "") + "]"}, "needs cluster, issuer and serviceAccounts"},
		"blank accounts":     {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", issA, `" "`) + "]"}, "needs cluster, issuer and serviceAccounts"},
		"http issuer":        {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", "http://a.example.com", ok) + "]"}, "not an https URL"},
		"not a list":         {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": `{"cluster":"a"}`}, "not a JSON list"},
		"unknown field":      {map[string]string{"CLEARANCE_FOREIGN_CLUSTERS": `[{"cluster":"a","issuer":"https://a","serviceAccounts":["x/y"],"jwks":"z"}]`}, "not a JSON list"},
		"list repeats the single issuer": {map[string]string{
			"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("b", issA, ok) + "]",
			"CLEARANCE_FOREIGN_ISSUER":   issA + "/", "CLEARANCE_FOREIGN_CLUSTER": "a", "CLEARANCE_FOREIGN_SERVICE_ACCOUNTS": "x/y"}, "already named"},
		"list repeats the single cluster": {map[string]string{
			"CLEARANCE_FOREIGN_CLUSTERS": "[" + one("a", issB, ok) + "]",
			"CLEARANCE_FOREIGN_ISSUER":   issA, "CLEARANCE_FOREIGN_CLUSTER": "a", "CLEARANCE_FOREIGN_SERVICE_ACCOUNTS": "x/y"}, "cluster name"},
	} {
		_, err := FromEnv(env(tc.env))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}
