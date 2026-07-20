package goauth_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestAuthenticationAndAuthorizationAreIndependent(t *testing.T) {
	cases := []struct {
		packages  string
		forbidden string
	}{
		{"./authentication/...", "github.com/justusschock/go-auth/authorization"},
		{"./authorization/...", "github.com/justusschock/go-auth/authentication"},
	}
	for _, test := range cases {
		t.Run(test.packages, func(t *testing.T) {
			output, err := exec.Command("go", "list", "-deps", test.packages).CombinedOutput()
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

func TestNoForbiddenDependency(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v: %s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		lower := strings.ToLower(dependency)
		if strings.HasSuffix(lower, "/forbidden") {
			t.Fatalf("forbidden dependency detected: %s", dependency)
		}
	}
}
