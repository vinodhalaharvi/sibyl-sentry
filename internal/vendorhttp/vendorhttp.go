// Package vendorhttp provides a thin HTTP client base used by Sentry's
// vendor-specific clients (okta, aws, github). Each vendor client embeds
// or composes a *Base to get authenticated GET-and-decode behaviour
// without re-implementing the plumbing.
//
// Why a shared package: the three vendor APIs differ in URL shape and
// data model but agree on the plumbing — Bearer-style auth header, JSON
// response decoding, non-2xx → error, optional debug logging. Three
// copies of that would drift; one copy with vendor-specific wrappers
// stays consistent.
package vendorhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Base is the embedded HTTP client used by every vendor client.
type Base struct {
	// BaseURL is the API root, e.g. "http://localhost:9001" or
	// "https://example.okta.com". No trailing slash.
	BaseURL string

	// AuthHeader is the value to send in the Authorization header,
	// e.g. "SSWS abc123", "Bearer ghp_xyz", "AWS4-HMAC-SHA256 ...".
	// Constructed by the vendor client's New() to bake the scheme in.
	AuthHeader string

	// HTTP is the underlying *http.Client. Callers may swap for retries,
	// custom timeouts, or test instrumentation. Defaults to a client
	// with a 30s timeout when constructed via NewBase.
	HTTP *http.Client

	// VendorName identifies the vendor for error messages, e.g. "okta".
	VendorName string
}

// NewBase constructs a Base with sensible defaults. BaseURL and authHeader
// must be non-empty. timeout defaults to 30s if zero.
func NewBase(baseURL, authHeader, vendorName string, timeout time.Duration) *Base {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Base{
		BaseURL:    baseURL,
		AuthHeader: authHeader,
		HTTP:       &http.Client{Timeout: timeout},
		VendorName: vendorName,
	}
}

// GetJSON issues an authenticated GET against {BaseURL}/{path} and decodes
// the response body into out. Returns wrapped error on transport failure,
// non-2xx status, or JSON decode failure. The path argument should NOT
// start with a slash — joinURL adds it.
func (b *Base) GetJSON(ctx context.Context, path string, out interface{}) error {
	u, err := b.joinURL(path)
	if err != nil {
		return fmt.Errorf("%s: build URL: %w", b.VendorName, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("%s: new request: %w", b.VendorName, err)
	}
	req.Header.Set("Authorization", b.AuthHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := b.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s GET %s: %w", b.VendorName, u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read up to 1KB of body to surface mock/real error envelopes
		// in the wrapped error. Long bodies would be log noise.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &HTTPError{
			Vendor:     b.VendorName,
			Method:     http.MethodGet,
			URL:        u,
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}
	if out == nil {
		// Caller doesn't care about the body — drain for keep-alive.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s GET %s: decode response: %w", b.VendorName, u, err)
	}
	return nil
}

// joinURL appends path (which may include /-delimited segments and ?query)
// to BaseURL. It validates that the resulting URL parses cleanly. Callers
// pass already-encoded path segments — we don't second-guess.
func (b *Base) joinURL(path string) (string, error) {
	if b.BaseURL == "" {
		return "", fmt.Errorf("BaseURL is empty")
	}
	// Strip any leading slash on path so concatenation is unambiguous.
	for len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	full := b.BaseURL + "/" + path
	// Light parse to surface obvious errors early.
	if _, err := url.Parse(full); err != nil {
		return "", err
	}
	return full, nil
}

// HTTPError is the typed error returned for non-2xx responses. Callers
// can errors.As to detect 404 (missing resource is not always an error)
// or 401 (auth misconfigured).
type HTTPError struct {
	Vendor     string
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	body := e.Body
	if len(body) > 200 {
		body = body[:200] + "..."
	}
	return fmt.Sprintf("%s %s %s: HTTP %d: %s",
		e.Vendor, e.Method, e.URL, e.StatusCode, body)
}

// IsNotFound reports whether err is an HTTPError with status 404.
// Useful when a missing fixture means "no such identity" rather than
// "the call failed."
func IsNotFound(err error) bool {
	he, ok := err.(*HTTPError)
	return ok && he.StatusCode == http.StatusNotFound
}
