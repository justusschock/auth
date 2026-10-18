package device_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/justusschock/go-auth/authentication"
	"github.com/justusschock/go-auth/authentication/device"
	"github.com/justusschock/go-auth/internal/authtest"
)

const (
	issuer     = "https://id.example"
	deviceCode = "device-code-SECRET-1234567890"
	userCode   = "WDJB-MJHT"
)

type tokenResponse struct {
	status int
	body   any
}

// fakeServer is an in-memory RFC 8628 authorization server. It is served via
// an in-memory http.RoundTripper so tests can run inside synctest bubbles.
type fakeServer struct {
	t              *testing.T
	mu             sync.Mutex
	deviceResponse map[string]any
	tokens         []tokenResponse
	tokenCalls     []time.Time
	tokenForms     []map[string]string
	deviceForms    []map[string]string
	discovery      map[string]any
	authHeaders    []string
}

func newFakeServer(t *testing.T) *fakeServer {
	return &fakeServer{
		t: t,
		deviceResponse: map[string]any{
			"device_code":               deviceCode,
			"user_code":                 userCode,
			"verification_uri":          issuer + "/device",
			"verification_uri_complete": issuer + "/device?user_code=" + userCode,
			"expires_in":                600,
			"interval":                  5,
		},
		discovery: map[string]any{
			"issuer":                        issuer,
			"authorization_endpoint":        issuer + "/authorize",
			"token_endpoint":                issuer + "/token",
			"device_authorization_endpoint": issuer + "/device/code",
			"jwks_uri":                      issuer + "/jwks",
		},
	}
}

func (s *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, http.StatusOK, s.discovery)
	case "/device/code":
		if r.Method != http.MethodPost || r.ParseForm() != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		s.deviceForms = append(s.deviceForms, flatten(r))
		writeJSON(w, http.StatusOK, s.deviceResponse)
	case "/token":
		if r.Method != http.MethodPost || r.ParseForm() != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		s.tokenCalls = append(s.tokenCalls, time.Now())
		s.tokenForms = append(s.tokenForms, flatten(r))
		s.authHeaders = append(s.authHeaders, r.Header.Get("Authorization"))
		if len(s.tokens) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
			return
		}
		next := s.tokens[0]
		s.tokens = s.tokens[1:]
		if text, ok := next.body.(string); ok {
			w.WriteHeader(next.status)
			_, _ = w.Write([]byte(text))
			return
		}
		writeJSON(w, next.status, next.body)
	default:
		http.NotFound(w, r)
	}
}

func flatten(r *http.Request) map[string]string {
	out := map[string]string{}
	for key := range r.PostForm {
		out[key] = r.PostForm.Get(key)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *fakeServer) client() *http.Client {
	return authtest.Client(s)
}

func explicitOptions(s *fakeServer) device.Options {
	return device.Options{
		DeviceAuthURL: issuer + "/device/code",
		TokenURL:      issuer + "/token",
		ClientID:      "dtc-cli",
		Scopes:        []string{"openid", "offline_access"},
		HTTPClient:    s.client(),
	}
}

func newClient(t *testing.T, options device.Options) *device.Client {
	t.Helper()
	client, err := device.New(context.Background(), options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func success() tokenResponse {
	return tokenResponse{status: http.StatusOK, body: map[string]any{
		"access_token":  "access-token",
		"token_type":    "Bearer",
		"refresh_token": "refresh-token",
		"expires_in":    3600,
		"id_token":      "header.payload.signature",
	}}
}

func oauthError(code string) tokenResponse {
	return tokenResponse{status: http.StatusBadRequest, body: map[string]any{"error": code, "error_description": "echo " + deviceCode}}
}

// FR-AUTH-19
func TestStartAndPollHonorsPendingAndSlowDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newFakeServer(t)
		server.tokens = []tokenResponse{oauthError("authorization_pending"), oauthError("slow_down"), oauthError("authorization_pending"), success()}
		client := newClient(t, explicitOptions(server))
		start := time.Now()

		authorization, err := client.Start(context.Background())
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		if authorization.UserCode != userCode || authorization.VerificationURI != issuer+"/device" ||
			authorization.VerificationURIComplete != issuer+"/device?user_code="+userCode {
			t.Fatalf("authorization = %#v", authorization)
		}
		if authorization.Interval != 5*time.Second || !authorization.ExpiresAt.Equal(start.Add(10*time.Minute)) {
			t.Fatalf("timing = %v, %v", authorization.Interval, authorization.ExpiresAt)
		}
		if dump := fmt.Sprintf("%v %+v %#v", authorization, authorization, authorization); strings.Contains(dump, deviceCode) {
			t.Fatal("formatted authorization leaked device code")
		}
		if form := server.deviceForms[0]; form["client_id"] != "dtc-cli" || form["scope"] != "openid offline_access" {
			t.Fatalf("device form = %v", form)
		}

		token, idToken, err := client.Poll(context.Background(), authorization)
		if err != nil {
			t.Fatalf("Poll() error = %v", err)
		}
		if token.AccessToken != "access-token" || token.RefreshToken != "refresh-token" || idToken != "header.payload.signature" {
			t.Fatalf("Poll() = %#v, %q", token, idToken)
		}
		// pending at 5s, slow_down at 10s, then the interval grows to 10s.
		want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}
		if len(server.tokenCalls) != len(want) {
			t.Fatalf("token calls = %d, want %d", len(server.tokenCalls), len(want))
		}
		for index, at := range server.tokenCalls {
			if got := at.Sub(start); got != want[index] {
				t.Fatalf("token call %d at %v, want %v", index, got, want[index])
			}
		}
		form := server.tokenForms[0]
		if form["grant_type"] != "urn:ietf:params:oauth:grant-type:device_code" || form["device_code"] != deviceCode || form["client_id"] != "dtc-cli" {
			t.Fatalf("token form = %v", form)
		}
		if _, ok := form["client_secret"]; ok || server.authHeaders[0] != "" {
			t.Fatal("public client sent a secret")
		}
	})
}

// FR-AUTH-19
func TestPollMapsTerminalErrors(t *testing.T) {
	tests := map[string]struct {
		response tokenResponse
		check    func(error) bool
	}{
		"access denied": {oauthError("access_denied"), func(err error) bool { return err == device.ErrAccessDenied }},
		"expired token": {oauthError("expired_token"), func(err error) bool { return err == authentication.ErrExpired }},
		"invalid client": {oauthError("invalid_client"), func(err error) bool {
			var oauthErr *device.Error
			return errors.As(err, &oauthErr) && oauthErr.Code == "invalid_client" && oauthErr.StatusCode == http.StatusBadRequest &&
				errors.Is(err, authentication.ErrUnauthenticated)
		}},
		"malformed code": {oauthError("bad\"code\x1b"), func(err error) bool {
			var oauthErr *device.Error
			return errors.As(err, &oauthErr) && oauthErr.Code == ""
		}},
		"server error page": {tokenResponse{status: http.StatusInternalServerError, body: "<html>" + deviceCode + "</html>"}, func(err error) bool {
			var oauthErr *device.Error
			return errors.As(err, &oauthErr) && oauthErr.StatusCode == http.StatusInternalServerError
		}},
		"missing access token": {tokenResponse{status: http.StatusOK, body: map[string]any{"token_type": "Bearer"}}, func(err error) bool {
			return errors.Is(err, device.ErrServer)
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newFakeServer(t)
				server.tokens = []tokenResponse{test.response}
				client := newClient(t, explicitOptions(server))
				authorization, err := client.Start(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				token, idToken, err := client.Poll(context.Background(), authorization)
				if token != nil || idToken != "" || !test.check(err) {
					t.Fatalf("Poll() = %v, %q, %v", token, idToken, err)
				}
				if strings.Contains(err.Error(), deviceCode) {
					t.Fatal("error leaked device code")
				}
			})
		})
	}
}

// FR-AUTH-19
func TestPollStopsAtAuthorizationExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newFakeServer(t)
		server.deviceResponse["expires_in"] = 8
		client := newClient(t, explicitOptions(server))
		start := time.Now()
		authorization, err := client.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.Poll(context.Background(), authorization); err != authentication.ErrExpired {
			t.Fatalf("Poll() error = %v, want ErrExpired", err)
		}
		if elapsed := time.Since(start); elapsed != 8*time.Second || len(server.tokenCalls) != 1 {
			t.Fatalf("expired after %v with %d calls", elapsed, len(server.tokenCalls))
		}
		if _, _, err := client.Poll(context.Background(), authorization); err != authentication.ErrExpired {
			t.Fatalf("Poll() after expiry error = %v, want ErrExpired", err)
		}
	})
}

// FR-AUTH-19
func TestPollReturnsCallerContextError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newFakeServer(t)
		client := newClient(t, explicitOptions(server))
		authorization, err := client.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if _, _, err := client.Poll(ctx, authorization); err != context.DeadlineExceeded {
			t.Fatalf("Poll() error = %v, want context.DeadlineExceeded", err)
		}
		if len(server.tokenCalls) != 2 {
			t.Fatalf("token calls = %d", len(server.tokenCalls))
		}
	})
}

// FR-AUTH-19
func TestPollDefaultsIntervalAndSendsClientSecret(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newFakeServer(t)
		delete(server.deviceResponse, "interval")
		server.tokens = []tokenResponse{success()}
		options := explicitOptions(server)
		options.ClientSecret = "client-secret"
		client := newClient(t, options)
		start := time.Now()
		authorization, err := client.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if authorization.Interval != 5*time.Second {
			t.Fatalf("interval = %v", authorization.Interval)
		}
		if _, _, err := client.Poll(context.Background(), authorization); err != nil {
			t.Fatal(err)
		}
		if server.tokenCalls[0].Sub(start) != 5*time.Second || !strings.HasPrefix(server.authHeaders[0], "Basic ") {
			t.Fatalf("call at %v with auth %q", server.tokenCalls[0].Sub(start), server.authHeaders[0])
		}
	})
}

// FR-AUTH-20
func TestStartRejectsUnsafeResponses(t *testing.T) {
	tests := map[string]func(map[string]any){
		"missing device code":      func(r map[string]any) { delete(r, "device_code") },
		"missing user code":        func(r map[string]any) { delete(r, "user_code") },
		"terminal escape":          func(r map[string]any) { r["user_code"] = "\x1b[31mABCD" },
		"non ascii user code":      func(r map[string]any) { r["user_code"] = "ÄBCD" },
		"missing verification uri": func(r map[string]any) { delete(r, "verification_uri") },
		"javascript uri":           func(r map[string]any) { r["verification_uri"] = "javascript:alert(1)" },
		"plain http uri":           func(r map[string]any) { r["verification_uri"] = "http://id.example/device" },
		"userinfo uri":             func(r map[string]any) { r["verification_uri"] = "https://user@id.example/device" },
		"bad complete uri":         func(r map[string]any) { r["verification_uri_complete"] = "file:///etc/passwd" },
		"missing expiry":           func(r map[string]any) { delete(r, "expires_in") },
		"negative expiry":          func(r map[string]any) { r["expires_in"] = -5 },
		"negative interval":        func(r map[string]any) { r["interval"] = -1 },
		"huge interval":            func(r map[string]any) { r["interval"] = 7200 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newFakeServer(t)
				mutate(server.deviceResponse)
				client := newClient(t, explicitOptions(server))
				authorization, err := client.Start(context.Background())
				if !errors.Is(err, device.ErrServer) {
					t.Fatalf("Start() = %#v, %v; want ErrServer", authorization, err)
				}
				if strings.Contains(err.Error(), deviceCode) {
					t.Fatal("error leaked device code")
				}
			})
		})
	}
}

// FR-AUTH-20
func TestStartMapsOAuthErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newFakeServer(t)
		client := newClient(t, device.Options{
			DeviceAuthURL: issuer + "/token", // returns OAuth errors
			TokenURL:      issuer + "/token",
			ClientID:      "dtc-cli",
			HTTPClient:    server.client(),
		})
		server.tokens = []tokenResponse{oauthError("unauthorized_client")}
		_, err := client.Start(context.Background())
		var oauthErr *device.Error
		if !errors.As(err, &oauthErr) || oauthErr.Code != "unauthorized_client" {
			t.Fatalf("Start() error = %v", err)
		}
	})
}

// FR-AUTH-19
func TestNewWithDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newFakeServer(t)
		server.tokens = []tokenResponse{success()}
		client := newClient(t, device.Options{Issuer: issuer, ClientID: "dtc-cli", Scopes: []string{"profile"}, HTTPClient: server.client()})
		authorization, err := client.Start(context.Background())
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		if scope := server.deviceForms[0]["scope"]; scope != "openid profile" {
			t.Fatalf("scope = %q", scope)
		}
		if _, idToken, err := client.Poll(context.Background(), authorization); err != nil || idToken == "" {
			t.Fatalf("Poll() = %q, %v", idToken, err)
		}
	})
}

// FR-AUTH-20
func TestNewDiscoveryFailures(t *testing.T) {
	tests := map[string]func(map[string]any){
		"no device endpoint": func(d map[string]any) { delete(d, "device_authorization_endpoint") },
		"issuer mismatch":    func(d map[string]any) { d["issuer"] = "https://evil.example" },
		"insecure endpoint":  func(d map[string]any) { d["device_authorization_endpoint"] = "http://id.example/device/code" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newFakeServer(t)
				mutate(server.discovery)
				if _, err := device.New(context.Background(), device.Options{Issuer: issuer, ClientID: "dtc-cli", HTTPClient: server.client()}); err == nil {
					t.Fatal("New() succeeded")
				}
			})
		})
	}
}

// FR-AUTH-20
func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()
	base := device.Options{DeviceAuthURL: issuer + "/device/code", TokenURL: issuer + "/token", ClientID: "dtc-cli"}
	tests := map[string]func(*device.Options){
		"missing client id":    func(o *device.Options) { o.ClientID = "" },
		"no endpoints":         func(o *device.Options) { o.DeviceAuthURL, o.TokenURL = "", "" },
		"missing token url":    func(o *device.Options) { o.TokenURL = "" },
		"issuer and endpoints": func(o *device.Options) { o.Issuer = issuer },
		"insecure endpoint":    func(o *device.Options) { o.TokenURL = "http://id.example/token" },
		"fragment endpoint":    func(o *device.Options) { o.TokenURL = issuer + "/token#x" },
		"duplicate scopes":     func(o *device.Options) { o.Scopes = []string{"a", "a"} },
		"scope with space":     func(o *device.Options) { o.Scopes = []string{"a b"} },
		"insecure issuer":      func(o *device.Options) { o.DeviceAuthURL, o.TokenURL, o.Issuer = "", "", "http://id.example" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := base
			mutate(&options)
			if _, err := device.New(context.Background(), options); err != authentication.ErrInvalidCredential {
				t.Fatalf("New() error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

// FR-AUTH-20
func TestPollRejectsInvalidAuthorization(t *testing.T) {
	t.Parallel()
	client := newClient(t, explicitOptions(newFakeServer(t)))
	if _, _, err := client.Poll(context.Background(), device.Authorization{ExpiresAt: time.Now().Add(time.Minute)}); err != authentication.ErrInvalidCredential {
		t.Fatalf("Poll() error = %v", err)
	}
}

// TestLoopbackServer exercises a real HTTP server outside a synctest bubble.
// FR-AUTH-19
func TestLoopbackServer(t *testing.T) {
	t.Parallel()
	server := newFakeServer(t)
	server.deviceResponse["interval"] = 1
	server.tokens = []tokenResponse{success()}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client := newClient(t, device.Options{
		DeviceAuthURL: httpServer.URL + "/device/code",
		TokenURL:      httpServer.URL + "/token",
		ClientID:      "dtc-cli",
		HTTPClient:    httpServer.Client(),
	})
	authorization, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if token, _, err := client.Poll(context.Background(), authorization); err != nil || token.AccessToken != "access-token" {
		t.Fatalf("Poll() = %v, %v", token, err)
	}
}
