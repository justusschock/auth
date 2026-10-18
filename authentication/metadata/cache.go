// Package metadata caches identity provider metadata documents (issuer and
// endpoint URLs, supported algorithms and scopes) in a go-cache Cache.
//
// The cache is an optimisation only: a cache miss, a cache error or an
// invalid cached document falls back to the Loader, and cache writes are best
// effort. Every document, cached or loaded, must name exactly the requested
// issuer and use https endpoints before it is returned.
package metadata

import (
	"context"
	"net/url"
	"slices"
	"time"

	"github.com/justusschock/go-auth/authentication"
	cache "github.com/justusschock/go-cache"
)

// Document is the subset of provider metadata this module uses.
type Document struct {
	Issuer          string
	AuthURL         string
	TokenURL        string
	JWKSURL         string
	LoadedAt        time.Time
	ExpiresAt       time.Time
	SigningAlgs     []string
	SupportedScopes []string
}

// Loader fetches the metadata document for an issuer.
type Loader interface {
	Load(context.Context, string) (Document, error)
}

// LoaderFunc adapts a function to Loader.
type LoaderFunc func(context.Context, string) (Document, error)

// Load calls f.
func (f LoaderFunc) Load(ctx context.Context, issuer string) (Document, error) {
	return f(ctx, issuer)
}

// Cache serves validated metadata documents from a backing cache with a
// loader fallback. It is safe for concurrent use when the backing cache and
// loader are.
type Cache struct {
	cache  cache.Cache[string, Document]
	loader Loader
	ttl    time.Duration
}

// NewCache returns a Cache. backing may be nil to disable caching; ttl <= 0
// disables cache writes.
func NewCache(backing cache.Cache[string, Document], loader Loader, ttl time.Duration) *Cache {
	return &Cache{cache: backing, loader: loader, ttl: ttl}
}

// Get returns the validated document for issuer. It returns
// authentication.ErrProviderNotFound when nothing is cached and no loader is
// configured, authentication.ErrInvalidCredential for an invalid loaded
// document, and loader errors unchanged.
func (c *Cache) Get(ctx context.Context, issuer string) (Document, error) {
	if c.cache != nil {
		if document, found, err := c.cache.Get(ctx, issuer); err == nil && found {
			if err := validateDocument(issuer, document); err == nil {
				return cloneDocument(document), nil
			}
		}
	}
	if c.loader == nil {
		return Document{}, authentication.ErrProviderNotFound
	}
	document, err := c.loader.Load(ctx, issuer)
	if err != nil {
		return Document{}, err
	}
	if err := validateDocument(issuer, document); err != nil {
		return Document{}, err
	}
	if c.cache != nil && c.ttl > 0 {
		_ = c.cache.SetWithTTL(ctx, issuer, cloneDocument(document), c.ttl)
	}
	return cloneDocument(document), nil
}

func validateDocument(issuer string, document Document) error {
	if document.Issuer != issuer || !httpsURL(document.Issuer) || !httpsURL(document.AuthURL) || !httpsURL(document.TokenURL) || !httpsURL(document.JWKSURL) {
		return authentication.ErrInvalidCredential
	}
	return nil
}

func httpsURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func cloneDocument(document Document) Document {
	document.SigningAlgs = slices.Clone(document.SigningAlgs)
	document.SupportedScopes = slices.Clone(document.SupportedScopes)
	return document
}
