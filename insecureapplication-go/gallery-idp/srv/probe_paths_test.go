package srv

import (
	"net/http"
	"testing"
)

// probePaths are well-known paths browsers and crawlers request
// automatically (favicon lookups, iOS home-screen icons, robots.txt) without
// any user-initiated navigation. GET / is registered as a catch-all in
// Handler() (net/http's ServeMux routes any unmatched path to the most
// specific pattern that fits, and "/" fits everything), so before these were
// registered explicitly, hitting any of them fell through to handleIndex --
// silently redirecting a logged-in user to their own gallery.
var probePaths = []string{
	"/favicon.ico",
	"/apple-touch-icon.png",
	"/apple-touch-icon-precomposed.png",
	"/robots.txt",
}

// TestProbePaths_NoContent_LoggedOut pins down that these paths never render
// the index page: they must resolve on their own instead of falling through
// to GET /'s handleIndex.
func TestProbePaths_NoContent_LoggedOut(t *testing.T) {
	ts, _ := newTestServer(t)

	for _, p := range probePaths {
		t.Run(p, func(t *testing.T) {
			resp, err := http.Get(ts.URL + p)
			if err != nil {
				t.Fatalf("get %s: %v", p, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("%s status = %d, want %d", p, resp.StatusCode, http.StatusNoContent)
			}
		})
	}
}

// TestProbePaths_NoContent_LoggedIn is the regression case: previously, a
// logged-in user's browser auto-requesting one of these paths (e.g. while
// the Consent Dialog is on screen) fell through to handleIndex, which
// redirects an authenticated user to /photos/{username} -- firing an
// unrelated request against the resource server as a side effect of an
// unrelated page load.
func TestProbePaths_NoContent_LoggedIn(t *testing.T) {
	ts, _ := newTestServer(t)
	client := loginAsKoen(t, ts.URL)

	for _, p := range probePaths {
		t.Run(p, func(t *testing.T) {
			resp, err := client.Get(ts.URL + p)
			if err != nil {
				t.Fatalf("get %s: %v", p, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("%s status = %d, want %d (must not fall through to handleIndex's redirect)", p, resp.StatusCode, http.StatusNoContent)
			}
		})
	}
}
