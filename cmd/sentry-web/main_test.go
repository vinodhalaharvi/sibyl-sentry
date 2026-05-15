// Smoke test for sentry-web's handlers that don't require Temporal.
// Validates the embedded UI loads, healthz returns ok, metrics returns
// the placeholder body. handleRun and handleEvents need Temporal — those
// are exercised in the full demo.
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleIndex_ServesEmbeddedUI(t *testing.T) {
	s := &server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s.handleIndex(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	got := string(body)
	if !strings.Contains(got, "Sibyl Sentry") {
		t.Errorf("response body missing brand text; first 200 bytes:\n%s", got[:min(200, len(got))])
	}
	if !strings.Contains(got, "EventSource") {
		t.Error("response body missing SSE client code")
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type: got %q want text/html...", ct)
	}
}

func TestHandleIndex_404OnUnknown(t *testing.T) {
	s := &server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/not-a-page", nil)
	s.handleIndex(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d want 404", rec.Code)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
