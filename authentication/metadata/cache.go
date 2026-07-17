package metadata

import (
	"context"
	"net/url"
	"slices"
	"time"

	"github.com/justusschock/go-auth/authentication"
	cache "github.com/justusschock/go-cache"
)

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

type Loader interface {
	Load(context.Context, string) (Document, error)
}

type LoaderFunc func(context.Context, string) (Document, error)

func (f LoaderFunc) Load(ctx context.Context, issuer string) (Document, error) {
	return f(ctx, issuer)
}

type Cache struct {
	cache  cache.Cache[string, Document]
	loader Loader
	ttl    time.Duration
}

func NewCache(backing cache.Cache[string, Document], loader Loader, ttl time.Duration) *Cache {
	return &Cache{cache: backing, loader: loader, ttl: ttl}
}

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
