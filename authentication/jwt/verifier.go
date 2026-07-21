package jwt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/justusschock/go-auth/authentication"
)

const (
	defaultMaxTokenBytes = 32 * 1024
	maxKeyIDBytes        = 256
)

// KeySource returns the verification key for a validated JWT key ID.
type KeySource interface {
	Key(context.Context, string) (any, error)
}

// ClaimsMapper maps verified JWT claims to a protocol-neutral principal.
type ClaimsMapper func(context.Context, jwt.MapClaims) (authentication.Principal, error)

// Options configures a signed JWT verifier.
type Options struct {
	Issuer        string
	Audiences     []string
	Algorithms    []string
	Keys          KeySource
	ClaimsMapper  ClaimsMapper
	Clock         func() time.Time
	ClockSkew     time.Duration
	MaxTokenBytes int
	MaxLifetime   time.Duration
}

// Verifier authenticates signed JWT credentials.
type Verifier struct {
	issuer        string
	audiences     []string
	algorithms    []string
	keys          KeySource
	mapper        ClaimsMapper
	clock         func() time.Time
	clockSkew     time.Duration
	maxTokenBytes int
	maxLifetime   time.Duration
}

var _ authentication.Authenticator = (*Verifier)(nil)

// NewVerifier returns a strict signed JWT verifier.
func NewVerifier(options Options) (*Verifier, error) {
	if invalidText(options.Issuer) || len(options.Audiences) == 0 || len(options.Algorithms) == 0 || options.Keys == nil {
		return nil, authentication.ErrInvalidCredential
	}
	if options.MaxLifetime <= 0 {
		return nil, authentication.ErrInvalidCredential
	}
	if hasDuplicates(options.Audiences) || hasDuplicates(options.Algorithms) {
		return nil, authentication.ErrInvalidCredential
	}
	for _, audience := range options.Audiences {
		if invalidText(audience) {
			return nil, authentication.ErrInvalidCredential
		}
	}
	for _, algorithm := range options.Algorithms {
		if invalidText(algorithm) {
			return nil, authentication.ErrInvalidCredential
		}
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	maxTokenBytes := options.MaxTokenBytes
	if maxTokenBytes <= 0 {
		maxTokenBytes = defaultMaxTokenBytes
	}
	mapper := options.ClaimsMapper
	if mapper == nil {
		mapper = defaultClaimsMapper
	}
	return &Verifier{
		issuer:        options.Issuer,
		audiences:     slices.Clone(options.Audiences),
		algorithms:    slices.Clone(options.Algorithms),
		keys:          options.Keys,
		mapper:        mapper,
		clock:         clock,
		clockSkew:     options.ClockSkew,
		maxTokenBytes: maxTokenBytes,
		maxLifetime:   options.MaxLifetime,
	}, nil
}

// Authenticate verifies a JWT credential and returns the mapped principal.
func (v *Verifier) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Principal, error) {
	if credential.Kind != "jwt" || len(credential.Token) == 0 || len(credential.Token) > v.maxTokenBytes {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}

	authTime := v.clock().UTC()
	claims := jwt.MapClaims{}
	options := []jwt.ParserOption{
		jwt.WithValidMethods(v.algorithms),
		jwt.WithIssuer(v.issuer),
		jwt.WithLeeway(v.clockSkew),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return authTime }),
	}
	options = append(options, jwt.WithAudience(v.audiences...))

	parser := jwt.NewParser(options...)
	token, err := parser.ParseWithClaims(string(credential.Token), claims, func(token *jwt.Token) (any, error) {
		kid, err := validatedKeyID(token)
		if err != nil {
			return nil, err
		}
		key, err := v.keys.Key(ctx, kid)
		if err != nil {
			return nil, errors.New("jwt: key unavailable")
		}
		return key, nil
	})
	if err != nil || token == nil || !token.Valid {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	if !validClaims(claims, v.maxLifetime) {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	principal, err := v.mapper(ctx, claims)
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	principal, err = principalWithEffectiveSkew(principal, authTime, v.clockSkew)
	if err != nil {
		return authentication.Principal{}, authentication.ErrUnauthenticated
	}
	return principal, nil
}

func validatedKeyID(token *jwt.Token) (string, error) {
	if token == nil || token.Method == nil || token.Method.Alg() == jwt.SigningMethodNone.Alg() {
		return "", errors.New("jwt: invalid signing method")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || invalidBoundedText(kid, maxKeyIDBytes) {
		return "", errors.New("jwt: invalid kid")
	}
	return kid, nil
}

func validClaims(claims jwt.MapClaims, maxLifetime time.Duration) bool {
	if maxLifetime <= 0 {
		return false
	}
	issuer, err := claims.GetIssuer()
	if err != nil || invalidText(issuer) {
		return false
	}
	subject, err := claims.GetSubject()
	if err != nil || invalidText(subject) {
		return false
	}
	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) == 0 || hasDuplicates([]string(audiences)) {
		return false
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return false
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return false
	}
	if notBefore, err := claims.GetNotBefore(); err != nil || (notBefore != nil && notBefore.After(expiresAt.Time)) {
		return false
	}
	if !issuedAt.Before(expiresAt.Time) {
		return false
	}
	if maxLifetime > 0 && expiresAt.Sub(issuedAt.Time) > maxLifetime {
		return false
	}
	return true
}

func validatePrincipalWithSkew(principal authentication.Principal, authTime time.Time, skew time.Duration) error {
	if err := authentication.ValidatePrincipal(principal, authTime); err == nil {
		return nil
	}
	if skew <= 0 {
		return authentication.ErrInvalidPrincipal
	}
	if principal.AuthenticatedAt.After(authTime.Add(skew)) {
		return authentication.ErrInvalidPrincipal
	}
	if !authTime.Before(principal.ExpiresAt.Add(skew)) {
		return authentication.ErrInvalidPrincipal
	}

	validationTime := authTime
	if principal.AuthenticatedAt.After(validationTime) {
		validationTime = principal.AuthenticatedAt
	}
	if !validationTime.Before(principal.ExpiresAt) {
		validationTime = principal.ExpiresAt.Add(-time.Nanosecond)
	}
	return authentication.ValidatePrincipal(principal, validationTime)
}

func principalWithEffectiveSkew(principal authentication.Principal, authTime time.Time, skew time.Duration) (authentication.Principal, error) {
	if err := validatePrincipalWithSkew(principal, authTime, skew); err != nil {
		return authentication.Principal{}, err
	}
	clone := principal.Clone()
	if clone.AuthenticatedAt.After(authTime) {
		clone.AuthenticatedAt = authTime
	}
	if !authTime.Before(clone.ExpiresAt) {
		clone.ExpiresAt = authTime.Add(time.Nanosecond)
	}
	if err := authentication.ValidatePrincipal(clone, authTime); err != nil {
		return authentication.Principal{}, err
	}
	return clone, nil
}

func defaultClaimsMapper(_ context.Context, claims jwt.MapClaims) (authentication.Principal, error) {
	issuer, err := claims.GetIssuer()
	if err != nil {
		return authentication.Principal{}, err
	}
	subject, err := claims.GetSubject()
	if err != nil {
		return authentication.Principal{}, err
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return authentication.Principal{}, errors.New("jwt: missing iat")
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return authentication.Principal{}, errors.New("jwt: missing exp")
	}
	return authentication.Principal{
		ID:              fmt.Sprintf("%s|%s", issuer, subject),
		Issuer:          issuer,
		Subject:         subject,
		AuthenticatedAt: issuedAt.Time.UTC(),
		ExpiresAt:       expiresAt.Time.UTC(),
		Methods:         []string{"jwt"},
	}, nil
}

func hasDuplicates(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func invalidText(value string) bool {
	return value == "" || !utf8.ValidString(value) || containsNUL(value)
}

func invalidBoundedText(value string, limit int) bool {
	return invalidText(value) || len(value) > limit
}

func containsNUL(value string) bool {
	for i := range len(value) {
		if value[i] == 0 {
			return true
		}
	}
	return false
}
