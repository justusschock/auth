package goauth_test

import (
	"os/exec"
	"strings"
	"testing"
)

// NFR-AUTH-05
func TestAuthenticationAndAuthorizationAreIndependent(t *testing.T) {
	cases := []struct {
		packages  string
		forbidden string
	}{
		{"./authentication/...", "github.com/justusschock/auth/authorization"},
		{"./authorization/...", "github.com/justusschock/auth/authentication"},
	}
	for _, test := range cases {
		t.Run(test.packages, func(t *testing.T) {
			output, err := exec.Command("go", "list", "-deps", "-test", test.packages).CombinedOutput()
			if err != nil {
				t.Fatalf("go list: %v: %s", err, output)
			}
			for _, dependency := range strings.Fields(string(output)) {
				if dependency == test.forbidden || strings.HasPrefix(dependency, test.forbidden+"/") {
					t.Fatalf("%s imports forbidden package %s", test.packages, dependency)
				}
			}
		})
	}
}

// TestDirectDependenciesAreAllowlisted keeps the library's direct imports to
// the third-party modules accepted in docs/adr (ADR-0003). Adding one needs
// an ADR and an entry here.
// NFR-AUTH-05
func TestDirectDependenciesAreAllowlisted(t *testing.T) {
	allowed := map[string]string{
		"github.com/beevik/etree":                          "saml",
		"github.com/cedar-policy/cedar-go":                 "authorization/cedar",
		"github.com/cedar-policy/cedar-go/ast":             "authorization/cedar", // same module; renders cedar.Policies (ADR-0012)
		"github.com/coreos/go-oidc/v3/oidc":                "oidc, device",
		"github.com/crewjam/saml":                          "saml",
		"github.com/golang-jwt/jwt/v5":                     "jwt",
		"github.com/justusschock/cache":                    "metadata",
		"github.com/justusschock/distributed-coordination": "session",
		"github.com/mattermost/xml-roundtrip-validator":    "saml",
		"github.com/russellhaering/goxmldsig":              "saml",
		"golang.org/x/oauth2":                              "oauth2, oidc, device",
	}
	output, err := exec.Command("go", "list", "-f", `{{range .Imports}}{{.}} {{end}}`, "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v: %s", err, output)
	}
	for _, imported := range strings.Fields(string(output)) {
		if !strings.Contains(strings.SplitN(imported, "/", 2)[0], ".") ||
			imported == "github.com/justusschock/auth" || strings.HasPrefix(imported, "github.com/justusschock/auth/") {
			continue // standard library or this module
		}
		if _, ok := allowed[imported]; !ok {
			t.Errorf("non-allowlisted direct dependency %s", imported)
		}
	}
}

// TestMiddlewareUsesOnlyStandardLibrary keeps transport middleware free of
// protocol implementations and third-party dependencies.
// NFR-AUTH-05
func TestMiddlewareUsesOnlyStandardLibrary(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./authentication/middleware").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v: %s", err, output)
	}
	allowed := map[string]bool{
		"github.com/justusschock/auth/authentication":            true,
		"github.com/justusschock/auth/authentication/middleware": true,
	}
	for _, dependency := range strings.Fields(string(output)) {
		if !allowed[dependency] {
			t.Fatalf("middleware imports non-standard package %s", dependency)
		}
	}
}
