package srv

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"gallery-idp/db"
)

// sessionCookieValue returns the current gallery_sid cookie value the
// client's jar holds for baseURL, or "" if none is set yet.
func sessionCookieValue(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	return ""
}

// backdateSession directly rewrites created_at/updated_at for a session row,
// bypassing the normal datetime('now') defaults, so tests don't have to
// sleep for real wall-clock time to exercise timeout behavior. Mirrors
// db/sessions_test.go's helper of the same name -- kept as a separate copy
// since db-package test helpers aren't importable from srv's tests, but the
// computation and format must stay identical: both write UTC
// time.DateTime-formatted text, matching what datetime('now') itself
// produces in this column.
func backdateSession(t *testing.T, d *db.DB, id string, createdAgo, updatedAgo time.Duration) {
	t.Helper()
	created := time.Now().Add(-createdAgo).UTC().Format(time.DateTime)
	updated := time.Now().Add(-updatedAgo).UTC().Format(time.DateTime)
	if _, err := d.Exec(`UPDATE sessions SET created_at = ?, updated_at = ? WHERE id = ?`, created, updated, id); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
}

// newNoRedirectClient returns a fresh, unauthenticated client with its own
// cookiejar and redirects disabled, so callers can inspect each 302's
// Location header directly. Unlike loginAsKoen, it does not log in.
func newNoRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// loginAfterUnauthenticatedAuthorize drives an unauthenticated GET to
// /oauth/authorize with params, asserts it bounces to /login, then logs in
// as koen/password and returns the login response's Location header for the
// caller to inspect the resume behavior.
func loginAfterUnauthenticatedAuthorize(t *testing.T, client *http.Client, baseURL string, params url.Values) string {
	t.Helper()

	resp, err := client.Get(baseURL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("authorize redirect = %q, want %q", loc, "/login")
	}

	loginResp, err := client.PostForm(baseURL+"/login", url.Values{"username": {"koen"}, "password": {"password"}})
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want %d", loginResp.StatusCode, http.StatusFound)
	}
	return loginResp.Header.Get("Location")
}

// TestLoginRedirect_PlainLogin pins down the redirect chain for a login that
// never goes through /oauth/authorize at all -- this is the one path that
// the pending front-loading fix must leave untouched.
func TestLoginRedirect_PlainLogin(t *testing.T) {
	ts, _ := newTestServer(t)
	client := newNoRedirectClient(t)

	resp, err := client.PostForm(ts.URL+"/login", url.Values{"username": {"koen"}, "password": {"password"}})
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("login redirect = %q, want %q", loc, "/")
	}

	resp2, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("index request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("index status = %d, want %d", resp2.StatusCode, http.StatusFound)
	}
	if loc := resp2.Header.Get("Location"); loc != "/photos/koen" {
		t.Errorf("index redirect = %q, want %q", loc, "/photos/koen")
	}
}

// TestOAuthAuthorize_ResumesAfterLogin pins down the resume behavior: an
// unauthenticated GET /oauth/authorize must resume back into the pending
// authorization request after login -- landing on the Consent Dialog for
// photoprint (Trusted=false) -- instead of losing that request's context and
// dropping the user on their own gallery.
func TestOAuthAuthorize_ResumesAfterLogin(t *testing.T) {
	// Seed()'s applyClientEnvOverride (db/seed.go) rewrites the seeded
	// "photoprint" client's client_id if CLIENT_ID/CLIENT_SECRET are set in
	// the environment (mirrors mongo-seed/seed.sh). Pin them to the seeded
	// defaults so this test's use of the literal "photoprint" client_id
	// doesn't depend on the developer's shell environment.
	t.Setenv("CLIENT_ID", "photoprint")
	t.Setenv("CLIENT_SECRET", "secret")

	ts, _ := newTestServer(t)

	const callback = "http://client.example/callback"

	tests := []struct {
		name         string
		responseType string
	}{
		{name: "code", responseType: "code"},
		{name: "token", responseType: "token"},
		{name: "hybrid", responseType: "code token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newNoRedirectClient(t)
			params := url.Values{
				"response_type": {tt.responseType},
				"client_id":     {"photoprint"},
				"redirect_uri":  {callback},
				"scope":         {"view_gallery"},
				"state":         {"s1"},
			}

			loginLoc := loginAfterUnauthenticatedAuthorize(t, client, ts.URL, params)
			if loginLoc != "/authorize" {
				t.Errorf("login redirect = %q, want %q (pending authorization request must resume, not be dropped)", loginLoc, "/authorize")
			}

			finalResp, err := client.Get(ts.URL + loginLoc)
			if err != nil {
				t.Fatalf("post-login request to %q: %v", loginLoc, err)
			}
			defer finalResp.Body.Close()
			body, err := io.ReadAll(finalResp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			if finalResp.StatusCode != http.StatusOK {
				t.Errorf("post-login status = %d, want %d (location=%s, body=%s)", finalResp.StatusCode, http.StatusOK, loginLoc, body)
			}
			if !strings.Contains(string(body), "Authorize PhotoPrint") {
				t.Errorf("post-login body does not contain consent dialog heading %q (location=%s, body=%s)", "Authorize PhotoPrint", loginLoc, body)
			}
			if !strings.Contains(string(body), `name="transaction_id"`) {
				t.Errorf("post-login body does not contain consent dialog transaction_id field (location=%s, body=%s)", loginLoc, body)
			}
		})
	}
}

// TestOAuthAuthorize_TrustedClientResumesAfterLogin covers the same resume
// path for a Trusted client: Trusted only skips the consent dialog, not
// authentication, so an unauthenticated request must still resume through
// login before the immediate grant can happen.
func TestOAuthAuthorize_TrustedClientResumesAfterLogin(t *testing.T) {
	ts, _ := newTestServer(t)
	client := newNoRedirectClient(t)

	const callback = "http://client.example/callback"
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"trusted-client"},
		"redirect_uri":  {callback},
		"scope":         {"view_gallery"},
		"state":         {"s1"},
	}

	loginLoc := loginAfterUnauthenticatedAuthorize(t, client, ts.URL, params)
	if loginLoc != "/authorize" {
		t.Fatalf("login redirect = %q, want %q (handleLoginSubmit must stay OAuth-agnostic: it only resumes into /authorize, it never grants directly)", loginLoc, "/authorize")
	}

	finalResp, err := client.Get(ts.URL + loginLoc)
	if err != nil {
		t.Fatalf("post-login request to %q: %v", loginLoc, err)
	}
	finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		t.Fatalf("post-login status = %d, want %d", finalResp.StatusCode, http.StatusFound)
	}
	if loc := finalResp.Header.Get("Location"); !strings.HasPrefix(loc, callback) {
		t.Errorf("resumed authorize redirect = %q, want prefix %q (Trusted client must auto-grant, not show a dialog)", loc, callback)
	}
}

// TestOAuthAuthorize_StaleAwaitingLoginDoesNotResume pins down the
// AwaitingLogin TTL: a request stashed more than 10 minutes ago must not be
// silently resumed just because the same browser happens to log in later.
// This is the case the old "resume whenever the query string is empty"
// heuristic could never catch, since it had no concept of staleness at all.
func TestOAuthAuthorize_StaleAwaitingLoginDoesNotResume(t *testing.T) {
	ts, database := newTestServer(t)
	client := newNoRedirectClient(t)

	const callback = "http://client.example/callback"
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"trusted-client"},
		"redirect_uri":  {callback},
		"scope":         {"view_gallery"},
		"state":         {"s1"},
	}

	resp, err := client.Get(ts.URL + "/oauth/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("authorize redirect = %q, want %q", loc, "/login")
	}

	// Reach into the stashed entry directly and backdate it past the
	// 10-minute AwaitingLogin TTL, standing in for the user walking away
	// from the login form and coming back much later.
	sid := sessionCookieValue(t, client, ts.URL)
	if sid == "" {
		t.Fatal("no session cookie set after the unauthenticated /authorize hit")
	}
	sess, err := database.GetSession(sid)
	if err != nil || sess == nil {
		t.Fatalf("get session %q: %v", sid, err)
	}
	if len(sess.PendingAuthz) != 1 {
		t.Fatalf("expected exactly one stashed pending entry, got %d", len(sess.PendingAuthz))
	}
	for txID, p := range sess.PendingAuthz {
		p.StashedAt = time.Now().Add(-11 * time.Minute)
		sess.PendingAuthz[txID] = p
	}
	if err := database.SetPendingAuthz(sid, sess.PendingAuthz); err != nil {
		t.Fatalf("backdate pending authz: %v", err)
	}

	loginResp, err := client.PostForm(ts.URL+"/login", url.Values{"username": {"koen"}, "password": {"password"}})
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	loginResp.Body.Close()
	if loc := loginResp.Header.Get("Location"); loc != "/" {
		t.Errorf("login redirect after an expired AwaitingLogin entry = %q, want %q (a stale stash must not resume)", loc, "/")
	}
}

// TestLogin_RegeneratesSessionID is the session-fixation defense: a
// successful login must never keep using the pre-login session id, since an
// attacker who seeded that id into the victim's browser (e.g. by setting the
// gallery_sid cookie themselves) would otherwise inherit the authenticated
// session too. The pre-login row is left in place, unlinked from any user,
// rather than deleted.
func TestLogin_RegeneratesSessionID(t *testing.T) {
	ts, database := newTestServer(t)
	client := newNoRedirectClient(t)

	// Touch the server once, unauthenticated, to obtain the pre-login
	// anonymous session cookie.
	resp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	resp.Body.Close()
	preLoginID := sessionCookieValue(t, client, ts.URL)
	if preLoginID == "" {
		t.Fatal("no session cookie set after the initial unauthenticated request")
	}

	loginResp, err := client.PostForm(ts.URL+"/login", url.Values{"username": {"koen"}, "password": {"password"}})
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want %d", loginResp.StatusCode, http.StatusFound)
	}

	postLoginID := sessionCookieValue(t, client, ts.URL)
	if postLoginID == "" {
		t.Fatal("no session cookie set after login")
	}
	if postLoginID == preLoginID {
		t.Errorf("session id unchanged across login (%q); expected a freshly regenerated id (session-fixation defense)", postLoginID)
	}

	oldSess, err := database.GetSession(preLoginID)
	if err != nil {
		t.Fatalf("get pre-login session: %v", err)
	}
	if oldSess == nil {
		t.Fatal("pre-login session row was deleted; it should be abandoned in place, not removed")
	}
	if oldSess.UserID.Valid {
		t.Errorf("pre-login session row got authenticated in place (user_id = %q); login must not reuse it", oldSess.UserID.String)
	}

	newSess, err := database.GetSession(postLoginID)
	if err != nil || newSess == nil {
		t.Fatalf("get post-login session %q: %v", postLoginID, err)
	}
	if !newSess.UserID.Valid {
		t.Error("post-login session row has no user_id set")
	}
}

// TestAuthenticatedRoute_DegradesAfterIdleTimeout confirms that once a login
// session's idle window has elapsed, GetSession's server-side enforcement
// (not just the browser honoring a cookie Max-Age) actually kicks in: a
// request against an authenticated-only route must behave as logged-out,
// not merely have a stale-but-still-accepted cookie.
func TestAuthenticatedRoute_DegradesAfterIdleTimeout(t *testing.T) {
	ts, database := newTestServer(t)
	client := loginAsKoen(t, ts.URL)

	sid := sessionCookieValue(t, client, ts.URL)
	if sid == "" {
		t.Fatal("no session cookie set after login")
	}
	backdateSession(t, database, sid, 1*time.Hour, 31*time.Minute)

	resp, err := client.Get(ts.URL + "/photos/koen")
	if err != nil {
		t.Fatalf("get /photos/koen: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status after idle timeout = %d, want %d (redirect to /login)", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("redirect after idle timeout = %q, want %q", loc, "/login")
	}
}
