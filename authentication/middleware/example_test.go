package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/justusschock/auth/authentication"
	"github.com/justusschock/auth/authentication/middleware"
)

// staticAuthenticator accepts one fixed bearer token.
type staticAuthenticator struct{}

func (staticAuthenticator) Authenticate(_ context.Context, credential authentication.Credential) (authentication.Principal, error) {
	if string(credential.Token) != "let-me-in" {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	return authentication.Principal{ID: "issuer|alice", Subject: "alice"}, nil
}

func ExampleHTTP() {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authentication.PrincipalFromContext(r.Context())
		_, _ = fmt.Fprintf(w, "hello %s", principal.Subject)
	})
	handler := middleware.HTTP(app, authentication.Chain(staticAuthenticator{}), middleware.WithRealm("example"))

	for _, header := range []string{"Bearer let-me-in", "Bearer wrong"} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", header)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusOK {
			fmt.Println(recorder.Code, recorder.Body.String())
			continue
		}
		fmt.Println(recorder.Code, recorder.Header().Get("WWW-Authenticate"))
	}
	// Output:
	// 200 hello alice
	// 401 Bearer realm="example", error="invalid_token"
}
