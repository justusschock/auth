package authentication_test

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/justusschock/go-auth/authentication"
)

func TestValidatePrincipalRequiresIdentityAndCurrentUTCLifetime(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0).UTC()
	valid := authentication.Principal{
		ID:              "https://id.example|subject",
		Issuer:          "https://id.example",
		Subject:         "subject",
		AuthenticatedAt: now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Minute),
	}

	if err := authentication.ValidatePrincipal(valid, now); err != nil {
		t.Fatalf("ValidatePrincipal(valid) error = %v", err)
	}

	tests := map[string]func(*authentication.Principal){
		"missing ID":              func(p *authentication.Principal) { p.ID = "" },
		"missing issuer":          func(p *authentication.Principal) { p.Issuer = "" },
		"missing subject":         func(p *authentication.Principal) { p.Subject = "" },
		"authenticated in future": func(p *authentication.Principal) { p.AuthenticatedAt = now.Add(time.Nanosecond) },
		"expired at boundary":     func(p *authentication.Principal) { p.ExpiresAt = now },
		"unordered lifetime":      func(p *authentication.Principal) { p.ExpiresAt = p.AuthenticatedAt },
		"non UTC authentication": func(p *authentication.Principal) {
			p.AuthenticatedAt = p.AuthenticatedAt.In(time.FixedZone("offset", 3600))
		},
		"non UTC expiry": func(p *authentication.Principal) { p.ExpiresAt = p.ExpiresAt.In(time.FixedZone("offset", 3600)) },
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			principal := valid
			mutate(&principal)
			if err := authentication.ValidatePrincipal(principal, now); !errors.Is(err, authentication.ErrInvalidPrincipal) {
				t.Fatalf("ValidatePrincipal() error = %v, want ErrInvalidPrincipal", err)
			}
		})
	}
}

func TestValidatePrincipalRejectsUnboundedOrMalformedTraitsAndMethods(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0).UTC()
	valid := authentication.Principal{
		ID:              "issuer|subject",
		Issuer:          "issuer",
		Subject:         "subject",
		AuthenticatedAt: now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Minute),
	}

	tests := map[string]func(*authentication.Principal){
		"empty trait name": func(p *authentication.Principal) {
			p.Traits = map[string][]string{"": {"value"}}
		},
		"oversized trait name": func(p *authentication.Principal) {
			p.Traits = map[string][]string{strings.Repeat("n", 1<<16): {"value"}}
		},
		"oversized trait value": func(p *authentication.Principal) {
			p.Traits = map[string][]string{"name": {strings.Repeat("v", 1<<20)}}
		},
		"invalid trait UTF-8": func(p *authentication.Principal) {
			p.Traits = map[string][]string{"name": {string([]byte{0xff})}}
		},
		"empty method": func(p *authentication.Principal) {
			p.Methods = []string{""}
		},
		"duplicate method": func(p *authentication.Principal) {
			p.Methods = []string{"jwt", "jwt"}
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			principal := valid
			mutate(&principal)
			if err := authentication.ValidatePrincipal(principal, now); !errors.Is(err, authentication.ErrInvalidPrincipal) {
				t.Fatalf("ValidatePrincipal() error = %v, want ErrInvalidPrincipal", err)
			}
		})
	}
}

func TestPrincipalCloneOwnsNestedStateAndSortsMethods(t *testing.T) {
	t.Parallel()

	original := authentication.Principal{
		Traits:  map[string][]string{"groups": {"admin", "user"}},
		Methods: []string{"saml", "jwt"},
	}
	cloned := original.Clone()

	if want := []string{"jwt", "saml"}; !reflect.DeepEqual(cloned.Methods, want) {
		t.Fatalf("Clone().Methods = %v, want %v", cloned.Methods, want)
	}
	original.Traits["groups"][0] = "mutated"
	original.Methods[0] = "mutated"
	if got := cloned.Traits["groups"][0]; got != "admin" {
		t.Fatalf("Clone().Traits aliases input: got %q", got)
	}
	if got := cloned.Methods[1]; got != "saml" {
		t.Fatalf("Clone().Methods aliases input: got %q", got)
	}

	var zero authentication.Principal
	zeroClone := zero.Clone()
	if zeroClone.Traits != nil || zeroClone.Methods != nil {
		t.Fatalf("Clone() changed nil state: %#v", zeroClone)
	}
}

func TestCredentialAndRequestClonesOwnMutableState(t *testing.T) {
	t.Parallel()

	credential := authentication.Credential{
		Kind:       "jwt",
		Token:      []byte("secret-token"),
		Attributes: map[string]string{"source": "header"},
	}
	credentialClone := credential.Clone()
	credential.Token[0] = 'X'
	credential.Attributes["source"] = "mutated"
	if string(credentialClone.Token) != "secret-token" || credentialClone.Attributes["source"] != "header" {
		t.Fatalf("Credential.Clone() aliases input: %#v", credentialClone)
	}

	begin := authentication.BeginRequest{Scopes: []string{"openid", "email"}}
	beginClone := begin.Clone()
	begin.Scopes[0] = "mutated"
	if got := beginClone.Scopes[0]; got != "openid" {
		t.Fatalf("BeginRequest.Clone() aliases input: got %q", got)
	}

	redirectURL, err := url.Parse("https://user:password@app.example/callback?x=1")
	if err != nil {
		t.Fatal(err)
	}
	redirect := authentication.Redirect{URL: redirectURL}
	redirectClone := redirect.Clone()
	redirect.URL.Host = "mutated.example"
	if got := redirectClone.URL.Host; got != "app.example" {
		t.Fatalf("Redirect.Clone() aliases input: got host %q", got)
	}
	if got := redirectClone.URL.User.Username(); got != "user" {
		t.Fatalf("Redirect.Clone() lost user info: got username %q", got)
	}
}

func TestAuthenticationErrorsDoNotContainCredentials(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		authentication.ErrInvalidPrincipal,
		authentication.ErrInvalidCredential,
		authentication.ErrUnauthenticated,
		authentication.ErrExpired,
		authentication.ErrReplay,
		authentication.ErrInvalidCallback,
		authentication.ErrProviderNotFound,
	} {
		if strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("error %q contains credential text", err)
		}
	}
}
