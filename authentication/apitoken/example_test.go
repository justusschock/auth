package apitoken_test

import (
	"context"
	"fmt"
	"time"

	"github.com/justusschock/go-auth/authentication"
	"github.com/justusschock/go-auth/authentication/apitoken"
)

func ExampleManager() {
	ctx := context.Background()
	manager, err := apitoken.NewManager(apitoken.Options{
		Store:  apitoken.NewMemoryStore(),
		Prefix: "app",
		Pepper: []byte("a-32-byte-or-longer-secret-pepper"),
	})
	if err != nil {
		panic(err)
	}

	// Issue returns the token exactly once; store only the record.
	token, record, err := manager.Issue(ctx, apitoken.IssueRequest{
		Principal: apitoken.Identity{ID: "https://id.example|alice", Issuer: "https://id.example", Subject: "alice"},
		Name:      "ci",
		Scopes:    []string{"runs:write"},
		TTL:       90 * 24 * time.Hour,
	})
	if err != nil {
		panic(err)
	}

	principal, err := manager.Authenticate(ctx, authentication.Credential{
		Kind:  authentication.CredentialKindBearer,
		Token: []byte(token),
	})
	fmt.Println(principal.Subject, principal.Traits[apitoken.ScopeTrait], err)

	_ = manager.Revoke(ctx, record.Principal.ID, record.ID)
	_, err = manager.Authenticate(ctx, authentication.Credential{
		Kind:  authentication.CredentialKindBearer,
		Token: []byte(token),
	})
	fmt.Println(err)
	// Output:
	// alice [runs:write] <nil>
	// authentication: unauthenticated
}
