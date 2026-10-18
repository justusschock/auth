package authtest_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/justusschock/go-auth/internal/authtest"
)

func TestClientServesHandlerInMemory(t *testing.T) {
	client := authtest.Client(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path + " " + string(body)))
	}))
	response, err := client.Post("https://id.example/token", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusTeapot || string(body) != "POST /token payload" || response.Request == nil {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
}
