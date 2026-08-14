package srv

import (
	"net/http"

	"gallery-idp/db"
)

// scopeMap mirrors config/config.json's `scopemap` in the original gallery:
// human-readable descriptions shown on the consent screen. It has no
// enforcement role -- see middleware.go's ensureScope, which is defined but
// never wired to a route.
var scopeMap = map[string]string{
	"view_gallery":   "View your photo gallery",
	"view_profile":   "View your profile",
	"edit_profile":   "Edit your profile",
	"delete_profile": "Delete your profile",
	"edit_picture":   "Edit your pictures",
	"delete_picture": "Delete your pictures",
	"upload_picture": "Upload new pictures",
	"list_users":     "List all users",
	"offline_access": "Access your data while you are offline",
	"*":              "Full access to your account",
}

// handleAuthorize is the OAuth 2.0 authorization endpoint (GET /authorize,
// also mounted at /oauth/authorize). It intentionally never validates that
// redirect_uri belongs to the requesting client -- see
// insecureapplication/gallery/controllers/oauthcontroller.js's
// authorizationValidate, and doc/OAuth2_PoC_Verification_Report.md PoC2.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")

	client, err := s.DB.GetClient(clientID)
	if err != nil || client == nil {
		s.renderError(w, r, http.StatusBadRequest, "Unknown client")
		return
	}

	user := userFromCtx(r)

	if client.Trusted {
		s.grantAndRedirect(w, r, client, user, redirectURI, scope, state)
		return
	}

	txID := newOpaqueID()
	sess := sessionFromCtx(r)
	pending := sess.PendingAuthz
	if pending == nil {
		pending = map[string]db.PendingAuthz{}
	}
	pending[txID] = db.PendingAuthz{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
	}
	if err := s.DB.SetPendingAuthz(sess.ID, pending); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "session error")
		return
	}

	scopes := splitScope(scope)
	s.render(w, http.StatusOK, "dialog", map[string]any{
		"TransactionID": txID,
		"User":          user,
		"Client":        client,
		"Scope":         scope,
		"Scopes":        scopes,
		"ScopeMap":      scopeMap,
	})
}

func (s *Server) grantAndRedirect(w http.ResponseWriter, r *http.Request, client *db.Client, user *db.User, redirectURI, scope, state string) {
	code := weakCode()
	if err := s.DB.CreateAuthCode(code, client.ClientID, user.ID, redirectURI, scope); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not grant code")
		return
	}
	noCacheHeaders(w)
	dest := redirectURI + "?code=" + code
	if state != "" {
		dest += "&state=" + state
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func splitScope(scope string) []string {
	var out []string
	cur := ""
	for _, r := range scope {
		if r == ' ' || r == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func noCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
