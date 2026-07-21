package sso

import (
	"strings"
	"unicode/utf8"

	"github.com/justusschock/go-auth/authentication"
)

type Registration struct {
	Provider authentication.FederatedProvider
	Domains  []string
}

type Registry struct {
	providers map[string]authentication.FederatedProvider
	domains   map[string]authentication.FederatedProvider
}

func NewRegistry(registrations []Registration) (*Registry, error) {
	registry := &Registry{
		providers: make(map[string]authentication.FederatedProvider, len(registrations)),
		domains:   make(map[string]authentication.FederatedProvider),
	}
	for _, registration := range registrations {
		if registration.Provider == nil {
			return nil, authentication.ErrInvalidCredential
		}
		name := normalize(registration.Provider.Name())
		if invalidText(name) || strings.Contains(name, "@") || strings.Contains(name, "/") {
			return nil, authentication.ErrInvalidCredential
		}
		if _, exists := registry.providers[name]; exists {
			return nil, authentication.ErrInvalidCredential
		}
		registry.providers[name] = registration.Provider
		for _, domain := range registration.Domains {
			normalized := normalize(domain)
			if invalidText(normalized) || strings.Contains(normalized, "@") || strings.Contains(normalized, "/") {
				return nil, authentication.ErrInvalidCredential
			}
			if _, exists := registry.domains[normalized]; exists {
				return nil, authentication.ErrInvalidCredential
			}
			registry.domains[normalized] = registration.Provider
		}
	}
	return registry, nil
}

func (r *Registry) Select(input string) (authentication.FederatedProvider, error) {
	normalized := normalize(input)
	if invalidText(normalized) || strings.Contains(normalized, "/") {
		return nil, authentication.ErrProviderNotFound
	}
	if provider, ok := r.providers[normalized]; ok {
		return provider, nil
	}
	if strings.Count(normalized, "@") == 1 {
		parts := strings.Split(normalized, "@")
		if parts[0] == "" || parts[1] == "" {
			return nil, authentication.ErrProviderNotFound
		}
		if provider, ok := r.domains[parts[1]]; ok {
			return provider, nil
		}
	}
	return nil, authentication.ErrProviderNotFound
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func invalidText(value string) bool {
	return value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0
}
