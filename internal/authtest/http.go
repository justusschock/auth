// Package authtest holds test helpers shared by this module's tests. It is
// not part of the public API.
package authtest

import (
	"net/http"
	"net/http/httptest"
)

// HandlerTransport is an http.RoundTripper that serves every request with
// Handler in memory. It opens no sockets, so tests that use it can run inside
// testing/synctest bubbles and in sandboxes without network access.
type HandlerTransport struct {
	Handler http.Handler
}

// RoundTrip serves r with t.Handler and returns the recorded response.
func (t HandlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
	}
	recorder := httptest.NewRecorder()
	t.Handler.ServeHTTP(recorder, r)
	response := recorder.Result()
	response.Request = r
	return response, nil
}

// Client returns an *http.Client whose requests are served by handler in
// memory.
func Client(handler http.Handler) *http.Client {
	return &http.Client{Transport: HandlerTransport{Handler: handler}}
}
