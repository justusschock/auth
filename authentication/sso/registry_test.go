package sso_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/justusschock/go-auth/authentication"
	"github.com/justusschock/go-auth/authentication/sso"
)

func TestRegistrySelectsExactNormalizedDomainsAndProviderNames(t *testing.T) {
	work := fakeProvider{name: "work"}
	partners := fakeProvider{name: "partners"}
	registry, err := sso.NewRegistry([]sso.Registration{
		{Provider: work, Domains: []string{"Example.COM"}},
		{Provider: partners, Domains: []string{"partners.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, err := registry.Select("alice@example.com"); err != nil || got.Name() != "work" {
		t.Fatalf("Select(email) = %v, %v; want work", got, err)
	}
	if got, err := registry.Select("WORK"); err != nil || got.Name() != "work" {
		t.Fatalf("Select(provider) = %v, %v; want work", got, err)
	}
	if _, err := registry.Select("alice@sub.example.com"); !errors.Is(err, authentication.ErrProviderNotFound) {
		t.Fatalf("Select(subdomain) error = %v, want ErrProviderNotFound", err)
	}
	if _, err := registry.Select("https://app.example/callback?provider=work"); !errors.Is(err, authentication.ErrProviderNotFound) {
		t.Fatalf("Select(redirect) error = %v, want ErrProviderNotFound", err)
	}
}

func TestRegistryRejectsDuplicateProvidersAndDomains(t *testing.T) {
	for name, registrations := range map[string][]sso.Registration{
		"duplicate provider": {
			{Provider: fakeProvider{name: "work"}},
			{Provider: fakeProvider{name: "WORK"}},
		},
		"duplicate domain": {
			{Provider: fakeProvider{name: "work"}, Domains: []string{"example.com"}},
			{Provider: fakeProvider{name: "partners"}, Domains: []string{"EXAMPLE.COM"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sso.NewRegistry(registrations); err == nil {
				t.Fatalf("NewRegistry succeeded for %s", name)
			}
		})
	}
}

func TestRegistryRejectsAmbiguousProviderNames(t *testing.T) {
	for _, name := range []string{"alice@example.com", "path/provider"} {
		_, err := sso.NewRegistry([]sso.Registration{{Provider: fakeProvider{name: name}}})
		if !errors.Is(err, authentication.ErrInvalidCredential) {
			t.Fatalf("NewRegistry provider %q error = %v, want ErrInvalidCredential", name, err)
		}
	}
}

type fakeProvider struct {
	name string
}

func (p fakeProvider) Name() string {
	return p.name
}

func (p fakeProvider) Begin(context.Context, authentication.BeginRequest) (authentication.Redirect, error) {
	return authentication.Redirect{URL: &url.URL{Scheme: "https", Host: "id.example"}}, nil
}

func (p fakeProvider) Complete(context.Context, authentication.Callback) (authentication.Principal, error) {
	return authentication.Principal{}, nil
}
