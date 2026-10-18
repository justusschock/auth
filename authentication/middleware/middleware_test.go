package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/justusschock/go-auth/authentication"
	"github.com/justusschock/go-auth/authentication/middleware"
)

const secretToken = "dtc_secretsecretsecretsecret"

// FR-AUTH-09
func TestCredentialFromAuthorizationHeader(t *testing.T) {
	t.Parallel()
	jws := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"
	tests := map[string]struct {
		value     string
		wantKind  string
		wantToken string
		wantErr   error
	}{
		"bearer":            {value: "Bearer " + secretToken, wantKind: authentication.CredentialKindBearer, wantToken: secretToken},
		"case insensitive":  {value: "bEaReR " + secretToken, wantKind: authentication.CredentialKindBearer, wantToken: secretToken},
		"extra spaces":      {value: "Bearer   " + secretToken, wantKind: authentication.CredentialKindBearer, wantToken: secretToken},
		"padding":           {value: "Bearer abc+/==", wantKind: authentication.CredentialKindBearer, wantToken: "abc+/=="},
		"jws":               {value: "Bearer " + jws, wantKind: authentication.CredentialKindJWT, wantToken: jws},
		"unsecured jws":     {value: "Bearer eyJh.e30.", wantKind: authentication.CredentialKindJWT, wantToken: "eyJh.e30."},
		"two segments":      {value: "Bearer a.b", wantKind: authentication.CredentialKindBearer, wantToken: "a.b"},
		"four segments":     {value: "Bearer a.b.c.d", wantKind: authentication.CredentialKindBearer, wantToken: "a.b.c.d"},
		"jws with plus":     {value: "Bearer a+.b.c", wantKind: authentication.CredentialKindBearer, wantToken: "a+.b.c"},
		"empty":             {value: "", wantErr: authentication.ErrUnauthenticated},
		"basic":             {value: "Basic dXNlcjpwYXNz", wantErr: authentication.ErrUnsupportedCredential},
		"scheme only":       {value: "Bearer", wantErr: authentication.ErrInvalidCredential},
		"empty token":       {value: "Bearer ", wantErr: authentication.ErrInvalidCredential},
		"only padding":      {value: "Bearer ==", wantErr: authentication.ErrInvalidCredential},
		"inner padding":     {value: "Bearer a=b", wantErr: authentication.ErrInvalidCredential},
		"trailing space":    {value: "Bearer abc ", wantErr: authentication.ErrInvalidCredential},
		"two tokens":        {value: "Bearer abc def", wantErr: authentication.ErrInvalidCredential},
		"tab separator":     {value: "Bearer\tabc", wantErr: authentication.ErrInvalidCredential},
		"control character": {value: "Bearer ab\x00c", wantErr: authentication.ErrInvalidCredential},
		"non ascii":         {value: "Bearer abcé", wantErr: authentication.ErrInvalidCredential},
		"leading space":     {value: " Bearer abc", wantErr: authentication.ErrInvalidCredential},
		"oversized":         {value: "Bearer " + strings.Repeat("a", middleware.MaxAuthorizationBytes), wantErr: authentication.ErrInvalidCredential},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			credential, err := middleware.CredentialFromAuthorizationHeader(test.value)
			if err != test.wantErr {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if err != nil {
				if strings.Contains(err.Error(), "dXNlcjpwYXNz") || len(credential.Token) != 0 {
					t.Fatal("rejected value leaked")
				}
				return
			}
			if credential.Kind != test.wantKind || string(credential.Token) != test.wantToken {
				t.Fatalf("credential = %q/%q", credential.Kind, credential.Token)
			}
			if credential.Attributes[middleware.SourceAttribute] != middleware.SourceAuthorization {
				t.Fatalf("attributes = %v", credential.Attributes)
			}
		})
	}
}

type recordingAuthenticator struct {
	seen []authentication.Credential
	err  error
}

func (a *recordingAuthenticator) Authenticate(_ context.Context, credential authentication.Credential) (authentication.Principal, error) {
	a.seen = append(a.seen, credential.Clone())
	if a.err != nil {
		return authentication.Principal{}, a.err
	}
	return authentication.Principal{ID: "user|" + string(credential.Token[:3]), Subject: "user"}, nil
}

type result struct {
	status    int
	challenge string
	body      string
	principal string
	called    bool
}

func serve(t *testing.T, handler func(http.Handler) http.Handler, mutate func(*http.Request)) result {
	t.Helper()
	var out result
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out.called = true
		if principal, ok := authentication.PrincipalFromContext(r.Context()); ok {
			out.principal = principal.ID
		}
		w.WriteHeader(http.StatusTeapot)
	})
	request := httptest.NewRequest(http.MethodGet, "https://api.example/runs", nil)
	if mutate != nil {
		mutate(request)
	}
	recorder := httptest.NewRecorder()
	handler(next).ServeHTTP(recorder, request)
	out.status = recorder.Code
	out.challenge = recorder.Header().Get("WWW-Authenticate")
	out.body = recorder.Body.String()
	return out
}

// FR-AUTH-08
func TestHTTPAuthenticatesBearerAndCookie(t *testing.T) {
	t.Parallel()
	auth := &recordingAuthenticator{}
	wrap := func(next http.Handler) http.Handler {
		return middleware.HTTP(next, auth, middleware.WithCookie("session", "session"), middleware.WithRealm("dtc"))
	}

	got := serve(t, wrap, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secretToken) })
	if got.status != http.StatusTeapot || got.principal != "user|dtc" {
		t.Fatalf("bearer result = %#v", got)
	}
	got = serve(t, wrap, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "session", Value: "abcdef"}) })
	if got.status != http.StatusTeapot || got.principal != "user|abc" {
		t.Fatalf("cookie result = %#v", got)
	}
	got = serve(t, wrap, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+secretToken)
		r.AddCookie(&http.Cookie{Name: "session", Value: "abcdef"})
	})
	if got.principal != "user|dtc" {
		t.Fatalf("header must win over cookie: %#v", got)
	}
	if len(auth.seen) != 3 || auth.seen[1].Kind != "session" || auth.seen[1].Attributes[middleware.SourceAttribute] != middleware.SourceCookie {
		t.Fatalf("seen credentials = %#v", auth.seen)
	}
}

// FR-AUTH-08
func TestHTTPRejections(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		authErr       error
		options       []middleware.Option
		mutate        func(*http.Request)
		wantStatus    int
		wantChallenge string
	}{
		"missing": {
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="dtc"`,
		},
		"rejected": {
			authErr:    authentication.ErrUnauthenticated,
			mutate:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secretToken) },
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="dtc", error="invalid_token"`,
		},
		"unsupported by authenticators": {
			authErr:    authentication.ErrUnsupportedCredential,
			mutate:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secretToken) },
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="dtc", error="invalid_token"`,
		},
		"basic scheme": {
			options:    []middleware.Option{middleware.WithAnonymous()},
			mutate:     func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="dtc"`,
		},
		"malformed": {
			mutate:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer a b") },
			wantStatus: http.StatusBadRequest, wantChallenge: `Bearer realm="dtc", error="invalid_request"`,
		},
		"multiple headers": {
			mutate: func(r *http.Request) {
				r.Header.Add("Authorization", "Bearer "+secretToken)
				r.Header.Add("Authorization", "Bearer other")
			},
			wantStatus: http.StatusBadRequest, wantChallenge: `Bearer realm="dtc", error="invalid_request"`,
		},
		"multiple cookies": {
			options: []middleware.Option{middleware.WithCookie("session", "session")},
			mutate: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "session", Value: "one"})
				r.AddCookie(&http.Cookie{Name: "session", Value: "two"})
			},
			wantStatus: http.StatusBadRequest, wantChallenge: `Bearer realm="dtc", error="invalid_request"`,
		},
		"oversized": {
			options:    []middleware.Option{middleware.WithMaxTokenBytes(8)},
			mutate:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secretToken) },
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="dtc", error="invalid_token"`,
		},
		"invalid with anonymous": {
			authErr:    authentication.ErrUnauthenticated,
			options:    []middleware.Option{middleware.WithAnonymous()},
			mutate:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+secretToken) },
			wantStatus: http.StatusUnauthorized, wantChallenge: `Bearer realm="dtc", error="invalid_token"`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			auth := &recordingAuthenticator{err: test.authErr}
			if test.authErr != nil {
				auth.err = errors.Join(test.authErr, errors.New("detail "+secretToken))
			}
			options := append([]middleware.Option{middleware.WithRealm("dtc")}, test.options...)
			got := serve(t, func(next http.Handler) http.Handler { return middleware.HTTP(next, auth, options...) }, test.mutate)
			if got.called || got.status != test.wantStatus || got.challenge != test.wantChallenge {
				t.Fatalf("result = %#v", got)
			}
			if strings.Contains(got.body, secretToken) || strings.Contains(got.body, "detail") {
				t.Fatal("response leaked credential or authenticator error")
			}
		})
	}
}

// FR-AUTH-08
func TestHTTPAnonymousPassthrough(t *testing.T) {
	t.Parallel()
	auth := &recordingAuthenticator{}
	got := serve(t, func(next http.Handler) http.Handler {
		return middleware.HTTP(next, auth, middleware.WithAnonymous(), middleware.WithCookie("session", "session"))
	}, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "session", Value: ""}) })
	if !got.called || got.status != http.StatusTeapot || got.principal != "" || len(auth.seen) != 0 {
		t.Fatalf("anonymous result = %#v", got)
	}
}

// FR-AUTH-08
func TestHTTPChallengeWithoutRealm(t *testing.T) {
	t.Parallel()
	got := serve(t, func(next http.Handler) http.Handler { return middleware.HTTP(next, &recordingAuthenticator{}) }, nil)
	if got.challenge != "Bearer" {
		t.Fatalf("challenge = %q", got.challenge)
	}
}

// FR-AUTH-08
func TestHTTPPanicsOnInvalidConfiguration(t *testing.T) {
	t.Parallel()
	next := http.NotFoundHandler()
	auth := &recordingAuthenticator{}
	tests := map[string]func(){
		"nil handler":      func() { middleware.HTTP(nil, auth) },
		"nil auth":         func() { middleware.HTTP(next, nil) },
		"nil option":       func() { middleware.HTTP(next, auth, nil) },
		"quoted realm":     func() { middleware.HTTP(next, auth, middleware.WithRealm(`a"b`)) },
		"bad cookie name":  func() { middleware.HTTP(next, auth, middleware.WithCookie("a b", "session")) },
		"empty cookieKind": func() { middleware.HTTP(next, auth, middleware.WithCookie("session", "")) },
		"zero max":         func() { middleware.HTTP(next, auth, middleware.WithMaxTokenBytes(0)) },
	}
	for name, construct := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("HTTP did not panic")
				}
			}()
			construct()
		})
	}
}

// FR-AUTH-08
func TestHTTPWithChainAcceptsAPITokenAndJWTShapes(t *testing.T) {
	t.Parallel()
	byKind := func(kind string) authentication.Authenticator {
		return authenticatorFunc(func(_ context.Context, c authentication.Credential) (authentication.Principal, error) {
			if c.Kind != kind {
				return authentication.Principal{}, authentication.ErrUnsupportedCredential
			}
			return authentication.Principal{ID: kind}, nil
		})
	}
	chain := authentication.Chain(byKind(authentication.CredentialKindBearer), byKind(authentication.CredentialKindJWT))
	wrap := func(next http.Handler) http.Handler { return middleware.HTTP(next, chain) }
	for value, want := range map[string]string{
		"Bearer " + secretToken: authentication.CredentialKindBearer,
		"Bearer eyJh.e30.c2ln":  authentication.CredentialKindJWT,
	} {
		got := serve(t, wrap, func(r *http.Request) { r.Header.Set("Authorization", value) })
		if got.principal != want {
			t.Fatalf("%s => %#v", value, got)
		}
	}
}

type authenticatorFunc func(context.Context, authentication.Credential) (authentication.Principal, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Principal, error) {
	return f(ctx, credential)
}
