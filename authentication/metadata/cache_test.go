package metadata_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authmetadata "github.com/justusschock/go-auth/authentication/metadata"
	cache "github.com/justusschock/go-cache"
)

// FR-AUTH-24
func TestCacheFallsBackToLoaderWhenCacheMissOrOutage(t *testing.T) {
	ctx := context.Background()
	document := authmetadata.Document{
		Issuer:          "https://id.example",
		AuthURL:         "https://id.example/authorize",
		TokenURL:        "https://id.example/token",
		JWKSURL:         "https://id.example/keys",
		LoadedAt:        time.Unix(100, 0).UTC(),
		ExpiresAt:       time.Unix(700, 0).UTC(),
		SigningAlgs:     []string{"RS256"},
		SupportedScopes: []string{"openid", "email"},
	}
	backing := &recordingCache{getErr: errors.New("cache unavailable")}
	loader := authmetadata.LoaderFunc(func(context.Context, string) (authmetadata.Document, error) {
		return document, nil
	})
	c := authmetadata.NewCache(backing, loader, time.Minute)

	got, err := c.Get(ctx, "https://id.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != document.Issuer || backing.sets != 1 {
		t.Fatalf("document=%#v sets=%d", got, backing.sets)
	}
}

// FR-AUTH-24
func TestCacheRejectsMismatchedIssuerAndInsecureEndpoints(t *testing.T) {
	for name, doc := range map[string]authmetadata.Document{
		"issuer mismatch": {
			Issuer: "https://other.example", AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token", JWKSURL: "https://id.example/keys",
		},
		"insecure auth": {
			Issuer: "https://id.example", AuthURL: "http://id.example/authorize", TokenURL: "https://id.example/token", JWKSURL: "https://id.example/keys",
		},
		"insecure token": {
			Issuer: "https://id.example", AuthURL: "https://id.example/authorize", TokenURL: "http://id.example/token", JWKSURL: "https://id.example/keys",
		},
		"insecure jwks": {
			Issuer: "https://id.example", AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token", JWKSURL: "http://id.example/keys",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := authmetadata.NewCache(&recordingCache{}, authmetadata.LoaderFunc(func(context.Context, string) (authmetadata.Document, error) {
				return doc, nil
			}), time.Minute)
			if _, err := c.Get(context.Background(), "https://id.example"); err == nil {
				t.Fatalf("Get succeeded for invalid document")
			}
		})
	}
}

// FR-AUTH-24
func TestCacheReloadsInvalidCachedDocument(t *testing.T) {
	valid := authmetadata.Document{
		Issuer: "https://id.example", AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token", JWKSURL: "https://id.example/keys",
	}
	backing := &recordingCache{
		value: authmetadata.Document{
			Issuer: "https://other.example", AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token", JWKSURL: "https://id.example/keys",
		},
		found: true,
	}
	c := authmetadata.NewCache(backing, authmetadata.LoaderFunc(func(context.Context, string) (authmetadata.Document, error) {
		return valid, nil
	}), time.Minute)

	got, err := c.Get(context.Background(), "https://id.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != valid.Issuer || backing.sets != 1 {
		t.Fatalf("document=%#v sets=%d", got, backing.sets)
	}
}

type recordingCache struct {
	value  authmetadata.Document
	found  bool
	getErr error
	sets   int
}

var _ cache.Cache[string, authmetadata.Document] = (*recordingCache)(nil)

func (c *recordingCache) Get(context.Context, string) (authmetadata.Document, bool, error) {
	return c.value, c.found, c.getErr
}

func (c *recordingCache) Set(context.Context, string, authmetadata.Document) error {
	c.sets++
	return nil
}

func (c *recordingCache) SetWithTTL(context.Context, string, authmetadata.Document, time.Duration) error {
	c.sets++
	return nil
}

func (c *recordingCache) Invalidate(context.Context, string) error {
	return nil
}

func (c *recordingCache) InvalidateAll(context.Context) error {
	return nil
}
