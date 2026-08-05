// Native Hanzo IAM identity verification for the KMS-facing ZAP port.
//
// The cryptography is hanzoai/iamsdk — IAM's own SDK, which resolves IAM's
// published signing keys (JWKS) and checks the signature and validity
// window. IAM's in-process embed was retired and retracted (hanzoai/iam
// pkg/iam go.mod: "IAM is a binary you run, not a library you link into
// your server; talk to it over HTTP with hanzoai/iamsdk/v2"), so the SDK
// is the supported way to verify an IAM credential.
//
// On top of the signature we check the two things the SDK cannot know for
// us: that the token came from OUR issuer, and that it speaks for an org
// this port serves.
//
// # Claim semantics
//
// Deliberately identical to luxfi/kms cmd/kms/auth.go, which has run this
// against real IAM tokens. Two token flavours reach us:
//
//   - Application token (client_credentials — what a KMS pod presents):
//     owner="admin", type="application", and the org rides as the prefix
//     of name per the <org>-<service> convention, e.g. name="lux-kms".
//   - User token: owner IS the org slug.
//
// Audience is NOT enforced, matching KMS: IAM's client_credentials grant
// does not pin an audience to the resource server today, so requiring one
// would refuse every real credential. Issuer + signature + org is the
// check that actually holds.
package api

import (
	"context"
	"fmt"
	"strings"

	iamsdk "github.com/hanzoai/iamsdk/v2/iamsdk"
)

// iamVerifier verifies IAM access tokens for one org.
type iamVerifier struct {
	client *iamsdk.Client
	issuer string
	org    string
}

// NewIAMVerifier builds the production IdentityVerifier.
//
// jwksFrom is the URL to fetch IAM's keys from — in-cluster in production,
// so verification doesn't egress. issuer is the public `iss` value tokens
// are minted with; the two differ whenever a gateway rewrites Host, which
// is why they are separate arguments rather than one endpoint.
//
// org is the org this port serves. A token minted for another org verifies
// cryptographically and is still refused: a valid signature says who you
// are, not what you may reach.
func NewIAMVerifier(jwksFrom, issuer, org string) (IdentityVerifier, error) {
	jwksFrom = strings.TrimRight(jwksFrom, "/")
	issuer = strings.TrimRight(issuer, "/")
	if jwksFrom == "" {
		return nil, fmt.Errorf("iam: JWKS endpoint is required")
	}
	if issuer == "" {
		issuer = jwksFrom
	}
	if org == "" {
		return nil, fmt.Errorf("iam: org is required")
	}
	return &iamVerifier{
		// Verification needs the endpoint (for JWKS) and nothing secret —
		// which is what keeps this side of the KMS path cycle-free.
		client: iamsdk.NewClient(jwksFrom, "", "", "", org, ""),
		issuer: issuer,
		org:    org,
	}, nil
}

// Verify checks the token and returns the principal it names. Every check
// must pass; returning a nil error grants threshold-signing authority.
func (v *iamVerifier) Verify(_ context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	// Signature against IAM's published keys, plus the validity window.
	claims, err := v.client.ParseJwtToken(token)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	// ParseJwtToken does not check the issuer, so a token minted by any
	// IAM whose key we happen to fetch would otherwise pass.
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("issuer: got %q want %q", claims.Issuer, v.issuer)
	}
	// A credential with no stated expiry cannot be aged out of a session,
	// so it would hold authority until the process restarts.
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("token has no expiry")
	}
	authorized := false
	for _, o := range tokenOrgs(claims) {
		if orgAuthorizes(o, v.org) {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, fmt.Errorf("org: token %v does not authorize %q", tokenOrgs(claims), v.org)
	}
	subject := claims.Subject
	if subject == "" {
		subject = claims.Owner + "/" + claims.Name
	}
	return &Identity{
		Subject: subject,
		Owner:   v.org,
		Expires: claims.ExpiresAt.Time,
	}, nil
}

// tokenOrgs returns the org slugs a token may act for, first non-empty
// source winning per source. Mirrors orgClaims.orgs() in luxfi/kms.
//
// "admin" and "built-in" are IAM's parent records, not orgs — treating
// either as an org slug would let any application token in the estate
// reach this port.
func tokenOrgs(c *iamsdk.Claims) []string {
	out := []string{}
	if c.Tag != "" {
		out = append(out, c.Tag)
	}
	if c.Type == "application" && c.Name != "" {
		if i := strings.Index(c.Name, "-"); i > 0 {
			out = append(out, c.Name[:i])
		}
	}
	if c.Owner != "" && c.Owner != "admin" && c.Owner != "built-in" {
		out = append(out, c.Owner)
	}
	return out
}

// orgAuthorizes reports whether a token's org slug reaches a requested
// org. Sub-scopes match on a hyphen boundary, so a token for "lux" reaches
// "lux-infra" but never "luxx". Mirrors luxfi/kms cmd/kms/auth.go.
func orgAuthorizes(tokenOrg, requested string) bool {
	return requested == tokenOrg || strings.HasPrefix(requested, tokenOrg+"-")
}
