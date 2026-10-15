// Package device implements an OAuth 2.0 Device Authorization Grant
// (RFC 8628) client for command-line tools on machines without a browser.
//
// Start requests a device and user code and returns what the user must see;
// Poll waits for the user to approve the request on another device and
// returns the issued tokens. Endpoints come from OpenID Connect discovery or
// explicit configuration. The returned ID token is not verified by this
// package; relying servers must verify it (for example with
// authentication/jwt or go-oidc) before trusting it.
package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/justusschock/go-auth/authentication"
	authoidc "github.com/justusschock/go-auth/authentication/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultInterval       = 5 * time.Second
	defaultHTTPTimeout    = 30 * time.Second
	maxDeviceCodeBytes    = 4096
	maxUserCodeBytes      = 256
	maxURIBytes           = 2048
	maxScopes             = 64
	maxScopeBytes         = 256
	maxErrorCodeBytes     = 64
	errorCodeAccessDenied = "access_denied"
	errorCodeExpiredToken = "expired_token"
)

var (
	// ErrAccessDenied reports that the user denied the authorization request.
	ErrAccessDenied = errors.New("device: access denied")
	// ErrServer reports a transport failure or an invalid authorization server
	// response.
	ErrServer = errors.New("device: authorization server request failed")
)

// Error is an OAuth error response from the authorization server. Code is the
// RFC 6749 error code when it is well formed and empty otherwise. Error
// matches authentication.ErrUnauthenticated with errors.Is.
type Error struct {
	Code       string
	StatusCode int
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("device: authorization server error (HTTP %d)", e.StatusCode)
	}
	return fmt.Sprintf("device: authorization server error %q (HTTP %d)", e.Code, e.StatusCode)
}

// Unwrap returns authentication.ErrUnauthenticated.
func (e *Error) Unwrap() error {
	return authentication.ErrUnauthenticated
}

// Options configures a Client. Set either Issuer, for OpenID Connect
// discovery, or both DeviceAuthURL and TokenURL. Endpoints must use https,
// except http on loopback hosts.
type Options struct {
	Issuer        string
	DeviceAuthURL string
	TokenURL      string
	ClientID      string
	// ClientSecret is optional; device clients are usually public. When set
	// it is sent with HTTP Basic authentication.
	ClientSecret string
	// Scopes are requested verbatim. With Issuer, "openid" is added when
	// missing so that an ID token is issued.
	Scopes []string
	// HTTPClient defaults to a client with a 30 second timeout.
	HTTPClient *http.Client
}

// Authorization is a pending device authorization. Show UserCode and
// VerificationURI (or VerificationURIComplete) to the user, then call Poll.
// DeviceCode is redacted when formatted.
type Authorization struct {
	DeviceCode              authoidc.Secret
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresAt               time.Time
	Interval                time.Duration
}

// Client runs device authorization flows for one OAuth client.
type Client struct {
	config     oauth2.Config
	httpClient *http.Client
}

// New validates options and, when Issuer is set, performs OpenID Connect
// discovery.
func New(ctx context.Context, options Options) (*Client, error) {
	if invalidText(options.ClientID) || (options.ClientSecret != "" && invalidText(options.ClientSecret)) {
		return nil, authentication.ErrInvalidCredential
	}
	scopes, err := validateScopes(options.Scopes)
	if err != nil {
		return nil, err
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	explicit := options.DeviceAuthURL != "" || options.TokenURL != ""
	var endpoint oauth2.Endpoint
	switch {
	case options.Issuer != "" && explicit:
		return nil, authentication.ErrInvalidCredential
	case options.Issuer != "":
		if !validServiceURL(options.Issuer) {
			return nil, authentication.ErrInvalidCredential
		}
		provider, err := coreosoidc.NewProvider(coreosoidc.ClientContext(ctx, httpClient), options.Issuer)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("%w: discovery: %w", ErrServer, err)
		}
		endpoint = provider.Endpoint()
		if endpoint.DeviceAuthURL == "" {
			return nil, fmt.Errorf("%w: issuer does not advertise a device_authorization_endpoint", ErrServer)
		}
		if !slices.Contains(scopes, coreosoidc.ScopeOpenID) {
			scopes = append([]string{coreosoidc.ScopeOpenID}, scopes...)
		}
	default:
		endpoint = oauth2.Endpoint{DeviceAuthURL: options.DeviceAuthURL, TokenURL: options.TokenURL}
	}
	if !validServiceURL(endpoint.DeviceAuthURL) || !validServiceURL(endpoint.TokenURL) {
		return nil, authentication.ErrInvalidCredential
	}
	endpoint.AuthURL = ""
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	if options.ClientSecret != "" {
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	return &Client{
		config: oauth2.Config{
			ClientID:     options.ClientID,
			ClientSecret: options.ClientSecret,
			Endpoint:     endpoint,
			Scopes:       scopes,
		},
		httpClient: httpClient,
	}, nil
}

// Start requests a new device authorization.
func (c *Client) Start(ctx context.Context) (Authorization, error) {
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}
	response, err := c.config.DeviceAuth(c.context(ctx))
	if err != nil {
		return Authorization{}, requestError(ctx, err)
	}
	now := time.Now().UTC()
	if !validCode(response.DeviceCode, maxDeviceCodeBytes) || !validCode(response.UserCode, maxUserCodeBytes) {
		return Authorization{}, fmt.Errorf("%w: invalid device or user code", ErrServer)
	}
	if !validVerificationURI(response.VerificationURI) ||
		(response.VerificationURIComplete != "" && !validVerificationURI(response.VerificationURIComplete)) {
		return Authorization{}, fmt.Errorf("%w: invalid verification URI", ErrServer)
	}
	if response.Expiry.IsZero() || !now.Before(response.Expiry) {
		return Authorization{}, fmt.Errorf("%w: missing or invalid expires_in", ErrServer)
	}
	if response.Interval < 0 || response.Interval > int64(time.Hour/time.Second) {
		return Authorization{}, fmt.Errorf("%w: invalid interval", ErrServer)
	}
	interval := time.Duration(response.Interval) * time.Second
	if interval == 0 {
		interval = defaultInterval
	}
	return Authorization{
		DeviceCode:              authoidc.NewSecret(response.DeviceCode),
		UserCode:                response.UserCode,
		VerificationURI:         response.VerificationURI,
		VerificationURIComplete: response.VerificationURIComplete,
		ExpiresAt:               response.Expiry.UTC(),
		Interval:                interval,
	}, nil
}

// Poll waits until the user completes the authorization and returns the
// token and the raw, unverified ID token (empty when none was issued). It
// polls at the authorization interval, waits 5 seconds longer after each
// slow_down response, and keeps waiting on authorization_pending. It returns
// authentication.ErrExpired when the authorization expires, ErrAccessDenied
// when the user denies it, an *Error for other OAuth errors, and ctx.Err()
// when ctx ends first.
func (c *Client) Poll(ctx context.Context, authorization Authorization) (*oauth2.Token, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	deviceCode := string(authorization.DeviceCode.Bytes())
	if !validCode(deviceCode, maxDeviceCodeBytes) || authorization.ExpiresAt.IsZero() || authorization.Interval < 0 {
		return nil, "", authentication.ErrInvalidCredential
	}
	if !time.Now().Before(authorization.ExpiresAt) {
		return nil, "", authentication.ErrExpired
	}
	interval := authorization.Interval
	if interval == 0 {
		interval = defaultInterval
	}
	token, err := c.config.DeviceAccessToken(c.context(ctx), &oauth2.DeviceAuthResponse{
		DeviceCode: deviceCode,
		Expiry:     authorization.ExpiresAt,
		Interval:   int64((interval + time.Second - 1) / time.Second),
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		if errors.Is(err, context.DeadlineExceeded) {
			// DeviceAccessToken bounds polling by the authorization expiry.
			return nil, "", authentication.ErrExpired
		}
		return nil, "", requestError(ctx, err)
	}
	if token == nil || token.AccessToken == "" {
		return nil, "", fmt.Errorf("%w: missing access token", ErrServer)
	}
	idToken, _ := token.Extra("id_token").(string)
	return token, idToken, nil
}

func (c *Client) context(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
}

// requestError maps oauth2 errors to package errors without including
// response bodies, which may echo request parameters.
func requestError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) {
		code := sanitizeErrorCode(retrieve.ErrorCode)
		switch code {
		case errorCodeAccessDenied:
			return ErrAccessDenied
		case errorCodeExpiredToken:
			return authentication.ErrExpired
		}
		status := 0
		if retrieve.Response != nil {
			status = retrieve.Response.StatusCode
		}
		return &Error{Code: code, StatusCode: status}
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%w: %w", ErrServer, urlErr)
	}
	return ErrServer
}

// sanitizeErrorCode keeps RFC 6749 error codes (%x20-21 / %x23-5B / %x5D-7E).
func sanitizeErrorCode(code string) string {
	if code == "" || len(code) > maxErrorCodeBytes {
		return ""
	}
	for index := range len(code) {
		c := code[index]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return ""
		}
	}
	return code
}

// validCode accepts printable ASCII only so codes are safe to show in a
// terminal.
func validCode(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validVerificationURI(value string) bool {
	return validCode(value, maxURIBytes) && validServiceURL(value)
}

func validateScopes(scopes []string) ([]string, error) {
	if len(scopes) > maxScopes {
		return nil, authentication.ErrInvalidCredential
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope == "" || len(scope) > maxScopeBytes {
			return nil, authentication.ErrInvalidCredential
		}
		for index := range len(scope) {
			c := scope[index]
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return nil, authentication.ErrInvalidCredential
			}
		}
		if _, dup := seen[scope]; dup {
			return nil, authentication.ErrInvalidCredential
		}
		seen[scope] = struct{}{}
	}
	return slices.Clone(scopes), nil
}

func validServiceURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && isLoopback(parsed.Hostname())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func invalidText(value string) bool {
	return value == "" || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0
}
