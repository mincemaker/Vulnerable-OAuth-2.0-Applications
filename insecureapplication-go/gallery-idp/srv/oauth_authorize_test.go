package srv

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"gallery-idp/db"
)

// newTestServer boots a full gallery-idp server against a fresh, migrated,
// seeded SQLite database, plus one extra "trusted-client" client (so tests
// can exercise the immediate-grant path in handleAuthorize without also
// having to drive the consent dialog).
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	database, err := db.Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.RunMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if err := database.Seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := database.CreateClient("trusted-client", "Trusted", "secret", true, ""); err != nil {
		t.Fatalf("create trusted client: %v", err)
	}

	tmpl, err := LoadTemplates()
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(database, t.TempDir(), tmpl, log)

	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// loginAsKoen logs the seeded "koen"/"password" user in and returns an
// http.Client carrying the resulting session cookie, with redirects
// disabled so callers can inspect each 302's Location header directly.
func loginAsKoen(t *testing.T, baseURL string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.PostForm(baseURL+"/login", url.Values{"username": {"koen"}, "password": {"password"}})
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	return client
}

// TestHandleAuthorize_ResponseType covers doc/OAuth2_PoC_Verification_Report.md
// PoC8: response_type=token/​code token must actually issue an
// implicit/hybrid grant (fragment-delivered access_token, no
// client-level allowlist, no refresh_token), response_type=code must be
// unaffected, and a missing/unsupported response_type must produce an RFC
// 6749 §4.1.2.1/§4.2.2.1 error redirect instead of a silently empty one.
func TestHandleAuthorize_ResponseType(t *testing.T) {
	ts := newTestServer(t)
	client := loginAsKoen(t, ts.URL)

	const callback = "http://client.example/callback"

	tests := []struct {
		name         string
		responseType string
		wantFragment bool
		wantError    string // "" if no error expected
		wantCode     bool
		wantToken    bool
	}{
		{name: "code", responseType: "code", wantFragment: false, wantCode: true},
		{name: "token", responseType: "token", wantFragment: true, wantToken: true},
		{name: "hybrid", responseType: "code token", wantFragment: true, wantCode: true, wantToken: true},
		{name: "missing_response_type", responseType: "", wantFragment: false, wantError: "invalid_request"},
		{name: "unsupported_response_type", responseType: "id_token", wantFragment: false, wantError: "unsupported_response_type"},
		{name: "token_plus_unsupported", responseType: "token id_token", wantFragment: true, wantError: "unsupported_response_type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := ts.URL + "/oauth/authorize?" + url.Values{
				"response_type": {tt.responseType},
				"client_id":     {"trusted-client"},
				"redirect_uri":  {callback},
				"scope":         {"view_gallery"},
				"state":         {"s1"},
			}.Encode()

			resp, err := client.Get(reqURL)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
			}

			loc := resp.Header.Get("Location")
			if !strings.HasPrefix(loc, callback) {
				t.Fatalf("redirect target = %q, want prefix %q", loc, callback)
			}
			rest := loc[len(callback):]
			if rest == "" {
				t.Fatalf("redirect has no query/fragment: %q", loc)
			}
			gotFragment := rest[0] == '#'
			if !gotFragment && rest[0] != '?' {
				t.Fatalf("redirect separator = %q, want '?' or '#' (location=%s)", string(rest[0]), loc)
			}
			if gotFragment != tt.wantFragment {
				t.Errorf("fragment separator = %v, want %v (location=%s)", gotFragment, tt.wantFragment, loc)
			}

			params, err := url.ParseQuery(rest[1:])
			if err != nil {
				t.Fatalf("parse params: %v", err)
			}
			if params.Get("state") != "s1" {
				t.Errorf("state = %q, want %q (state must round-trip regardless of response_type)", params.Get("state"), "s1")
			}

			if tt.wantError != "" {
				if got := params.Get("error"); got != tt.wantError {
					t.Errorf("error = %q, want %q (location=%s)", got, tt.wantError, loc)
				}
				if params.Get("code") != "" || params.Get("access_token") != "" {
					t.Errorf("error response must not also carry a grant (location=%s)", loc)
				}
				return
			}
			if got := params.Get("error"); got != "" {
				t.Fatalf("unexpected error=%q for response_type=%q (location=%s)", got, tt.responseType, loc)
			}

			if hasCode := params.Get("code") != ""; hasCode != tt.wantCode {
				t.Errorf("code present = %v, want %v (location=%s)", hasCode, tt.wantCode, loc)
			}
			if hasToken := params.Get("access_token") != ""; hasToken != tt.wantToken {
				t.Errorf("access_token present = %v, want %v (location=%s)", hasToken, tt.wantToken, loc)
			}
			if tt.wantToken && params.Get("token_type") != "Bearer" {
				t.Errorf("token_type = %q, want %q", params.Get("token_type"), "Bearer")
			}
			// RFC 6749 §4.2.2: Implicit/hybrid grants must never include a
			// refresh_token, since there is no client authentication at all
			// in this flow.
			if params.Get("refresh_token") != "" {
				t.Errorf("refresh_token must never be issued via response_type=%q, got %q (location=%s)", tt.responseType, params.Get("refresh_token"), loc)
			}
		})
	}
}
