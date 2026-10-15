package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/justusschock/go-auth/authentication"
)

const defaultMaxTokenBytes = 8 << 10

type config struct {
	realm         string
	cookieName    string
	cookieKind    string
	anonymous     bool
	maxTokenBytes int
}

// Option configures HTTP.
type Option func(*config)

// WithRealm sets the realm reported in WWW-Authenticate challenges. It must
// be printable ASCII without quotes or backslashes.
func WithRealm(realm string) Option {
	return func(c *config) { c.realm = realm }
}

// WithCookie also reads credentials of the given kind from the named cookie
// when no Authorization header is present. Cookie authentication is
// vulnerable to cross-site request forgery; callers must add CSRF protection
// (for example SameSite cookies plus origin checks) for state-changing routes.
func WithCookie(name string, kind string) Option {
	return func(c *config) {
		c.cookieName = name
		c.cookieKind = kind
	}
}

// WithAnonymous passes requests that carry no credential to the next handler
// without a principal. Requests that carry an invalid credential are still
// rejected.
func WithAnonymous() Option {
	return func(c *config) { c.anonymous = true }
}

// WithMaxTokenBytes bounds accepted token sizes. The default is 8 KiB.
func WithMaxTokenBytes(limit int) Option {
	return func(c *config) { c.maxTokenBytes = limit }
}

type handler struct {
	next   http.Handler
	auth   authentication.Authenticator
	config config
}

// HTTP returns a handler that authenticates requests with auth and stores the
// principal with authentication.ContextWithPrincipal before calling next.
//
// Credentials come from a single "Authorization: Bearer" header (see
// CredentialFromAuthorizationHeader) or, when configured, a single cookie.
// Missing credentials and other Authorization schemes yield 401 (a scheme
// other than Bearer is rejected even WithAnonymous), malformed or ambiguous
// credentials 400, and rejected credentials 401, each with an RFC 6750 WWW-Authenticate challenge
// and a generic body that never includes credential material or
// authenticator errors.
//
// HTTP panics when next or auth is nil or an option is invalid.
func HTTP(next http.Handler, auth authentication.Authenticator, options ...Option) http.Handler {
	if next == nil || auth == nil {
		panic("middleware: HTTP requires a handler and an authenticator")
	}
	cfg := config{maxTokenBytes: defaultMaxTokenBytes}
	for _, option := range options {
		if option == nil {
			panic("middleware: nil option")
		}
		option(&cfg)
	}
	if !validRealm(cfg.realm) {
		panic("middleware: invalid realm")
	}
	if cfg.cookieName != "" || cfg.cookieKind != "" {
		if !validHTTPToken(cfg.cookieName) || strings.TrimSpace(cfg.cookieKind) == "" {
			panic("middleware: invalid cookie configuration")
		}
	}
	if cfg.maxTokenBytes <= 0 || cfg.maxTokenBytes > MaxAuthorizationBytes {
		panic("middleware: invalid token size limit")
	}
	return &handler{next: next, auth: auth, config: cfg}
}

type outcome int

const (
	present     outcome = iota // a credential was extracted
	absent                     // no credential, or only an unsupported scheme
	malformed                  // malformed or ambiguous credential
	unusable                   // well-formed but not acceptable, e.g. oversized
	unsupported                // another Authorization scheme
)

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	credential, result := h.credential(r)
	switch result {
	case present:
	case absent:
		if h.config.anonymous {
			h.next.ServeHTTP(w, r)
			return
		}
		h.challenge(w, http.StatusUnauthorized, "")
		return
	case unsupported:
		// RFC 6750 section 3.1: no error code for unsupported methods.
		h.challenge(w, http.StatusUnauthorized, "")
		return
	case malformed:
		h.challenge(w, http.StatusBadRequest, "invalid_request")
		return
	default:
		h.challenge(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	principal, err := h.auth.Authenticate(r.Context(), credential)
	clear(credential.Token)
	if err != nil || principal.ID == "" {
		h.challenge(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	h.next.ServeHTTP(w, r.WithContext(authentication.ContextWithPrincipal(r.Context(), principal)))
}

func (h *handler) credential(r *http.Request) (authentication.Credential, outcome) {
	values := r.Header.Values("Authorization")
	switch {
	case len(values) > 1:
		return authentication.Credential{}, malformed
	case len(values) == 1:
		credential, err := CredentialFromAuthorizationHeader(values[0])
		switch {
		case errors.Is(err, authentication.ErrUnsupportedCredential):
			return authentication.Credential{}, unsupported
		case err != nil:
			return authentication.Credential{}, malformed
		case len(credential.Token) > h.config.maxTokenBytes:
			return authentication.Credential{}, unusable
		}
		return credential, present
	}
	if h.config.cookieName == "" {
		return authentication.Credential{}, absent
	}
	cookies := r.CookiesNamed(h.config.cookieName)
	switch {
	case len(cookies) == 0:
		return authentication.Credential{}, absent
	case len(cookies) > 1:
		return authentication.Credential{}, malformed
	case cookies[0].Value == "":
		return authentication.Credential{}, absent
	case len(cookies[0].Value) > h.config.maxTokenBytes:
		return authentication.Credential{}, unusable
	}
	return authentication.Credential{
		Kind:       h.config.cookieKind,
		Token:      []byte(cookies[0].Value),
		Attributes: map[string]string{SourceAttribute: SourceCookie},
	}, present
}

func (h *handler) challenge(w http.ResponseWriter, status int, code string) {
	var challenge strings.Builder
	challenge.WriteString("Bearer")
	separator := " "
	if h.config.realm != "" {
		challenge.WriteString(separator + `realm="` + h.config.realm + `"`)
		separator = ", "
	}
	if code != "" {
		challenge.WriteString(separator + `error="` + code + `"`)
	}
	header := w.Header()
	header.Set("WWW-Authenticate", challenge.String())
	header.Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}

func validRealm(realm string) bool {
	for index := range len(realm) {
		c := realm[index]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return len(realm) <= 256
}
