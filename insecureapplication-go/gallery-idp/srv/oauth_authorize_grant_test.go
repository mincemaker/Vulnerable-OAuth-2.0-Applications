package srv

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gallery-idp/db"
)

// TestHandleAuthorize_TrustedGrantFailure_DoesNotClearPending pins down the
// double-write fix: when grantAndRedirect fails partway through (it already
// rendered an error response itself), handleAuthorize's Trusted-client
// branch must NOT go on to delete/rewrite the resumed pending entry -- that
// entry describes a request the user never actually got granted, and
// discarding it silently would strand them with no way to retry.
//
// CreateAuthCode is made to fail deterministically by dropping the
// authorization_codes table out from under it, while leaving every other
// table (clients, sessions, users) intact -- so GetClient and everything
// else handleAuthorize does before the grant attempt keeps working
// normally, and only the grant itself fails.
func TestHandleAuthorize_TrustedGrantFailure_DoesNotClearPending(t *testing.T) {
	_, database := newTestServer(t)

	u, err := database.GetUserByUsername("koen")
	if err != nil || u == nil {
		t.Fatalf("get seeded user koen: %v", err)
	}
	client, err := database.GetClient("trusted-client")
	if err != nil || client == nil {
		t.Fatalf("get trusted-client: %v", err)
	}

	if _, err := database.Exec(`DROP TABLE authorization_codes`); err != nil {
		t.Fatalf("drop authorization_codes: %v", err)
	}

	sess := &db.Session{
		ID: "sess-grant-fail",
		PendingAuthz: map[string]db.PendingAuthz{
			"tx-1": {
				ClientID:      client.ClientID,
				RedirectURI:   "http://client.example/callback",
				Scope:         "view_gallery",
				ResponseType:  "code",
				AwaitingLogin: true,
				StashedAt:     time.Now(),
			},
		},
	}

	tmpl, err := LoadTemplates()
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(database, t.TempDir(), tmpl, log)

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	ctx := context.WithValue(req.Context(), ctxKeySession, sess)
	ctx = context.WithValue(ctx, ctxKeyUser, u)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	server.handleAuthorize(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (grant should have failed via the dropped table)", w.Result().StatusCode, http.StatusInternalServerError)
	}
	if _, ok := sess.PendingAuthz["tx-1"]; !ok {
		t.Error("pending entry was deleted even though the grant failed; the resumeTxID cleanup must be gated on grantAndRedirect succeeding")
	}
}
