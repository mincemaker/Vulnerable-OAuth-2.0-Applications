package srv

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

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
//
// It also never restricts which response_type a client may request: any
// registered client -- including "photoprint", which is meant to be a
// server-side app confined to the authorization_code flow -- can be switched
// to Implicit Grant (response_type=token) or the hybrid (response_type=code
// token) simply by changing the query parameter, with no server-side
// allowlist to stop it. See doc/OAuth2_PoC_Verification_Report.md PoC8.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	responseType := q.Get("response_type")

	client, err := s.DB.GetClient(clientID)
	if err != nil || client == nil {
		s.renderError(w, r, http.StatusBadRequest, "Unknown client")
		return
	}

	// RFC 6749 §4.1.2.1 / §4.2.2.1: an invalid or unsupported response_type
	// is reported back via a redirect to redirect_uri (this app never
	// validates redirect_uri against the client's registration -- see PoC2
	// above -- so it's safe to redirect here without a prior allowlist
	// check), not by showing the consent screen.
	if errCode := invalidResponseTypeError(responseType); errCode != "" {
		noCacheHeaders(w)
		dest := redirectURI + redirectSeparator(wantsToken(responseType)) + "error=" + errCode
		if state != "" {
			dest += "&state=" + state
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}

	user := userFromCtx(r)

	if client.Trusted {
		s.grantAndRedirect(w, r, client, user, redirectURI, scope, state, responseType)
		return
	}

	txID := newOpaqueID()
	sess := sessionFromCtx(r)
	pending := sess.PendingAuthz
	if pending == nil {
		pending = map[string]db.PendingAuthz{}
	}
	pending[txID] = db.PendingAuthz{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Scope:        scope,
		State:        state,
		ResponseType: responseType,
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

// grantAndRedirect issues whatever grants responseType asks for and
// redirects back to the client with them. Callers (handleAuthorize,
// handleDecision) only ever pass a responseType that already passed
// invalidResponseTypeError, so it is always exactly "code", "token", or
// "code token" here. "code" mints an authorization_code, as before. "token"
// (alone or as part of "code token") mints an access_token directly --
// Implicit Grant, with no client authentication at any point and (per RFC
// 6749 §4.2.2, followed here deliberately for realism) no refresh_token.
// Per spec, anything that includes "token" goes in the URL fragment rather
// than the query string; grantAndRedirect switches on that automatically.
func (s *Server) grantAndRedirect(w http.ResponseWriter, r *http.Request, client *db.Client, user *db.User, redirectURI, scope, state, responseType string) {
	wantToken := wantsToken(responseType)
	wantCode := wantsCode(responseType)

	values := url.Values{}
	if wantCode {
		code := weakCode()
		if err := s.DB.CreateAuthCode(code, client.ClientID, user.ID, redirectURI, scope); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "could not grant code")
			return
		}
		values.Set("code", code)
	}
	if wantToken {
		accessToken := weakToken()
		if err := s.DB.CreateAccessToken(accessToken, client.ClientID, user.ID, scope); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "could not grant token")
			return
		}
		values.Set("access_token", accessToken)
		values.Set("token_type", "Bearer")
	}
	if state != "" {
		values.Set("state", state)
	}

	noCacheHeaders(w)
	http.Redirect(w, r, redirectURI+redirectSeparator(wantToken)+values.Encode(), http.StatusFound)
}

// wantsCode reports whether responseType explicitly asks for an
// authorization code ("code" or "code token").
func wantsCode(responseType string) bool {
	return hasResponseTypeValue(responseType, "code")
}

// wantsToken reports whether responseType asks for an access token
// (Implicit Grant, alone or as part of the "code token" hybrid).
func wantsToken(responseType string) bool {
	return hasResponseTypeValue(responseType, "token")
}

func hasResponseTypeValue(responseType, want string) bool {
	return slices.Contains(strings.Fields(responseType), want)
}

// invalidResponseTypeError returns the RFC 6749 error code for responseType,
// or "" if it's one of the supported values ("code", "token", "code token",
// in either order). response_type is a REQUIRED parameter (§3.1.1), so a
// missing one is "invalid_request" (§4.1.2.1: missing required parameter);
// anything present but not built entirely out of "code"/"token" values is
// "unsupported_response_type" (§4.1.2.1 / §4.2.2.1).
func invalidResponseTypeError(responseType string) string {
	if responseType == "" {
		return "invalid_request"
	}
	for v := range strings.FieldsSeq(responseType) {
		if v != "code" && v != "token" {
			return "unsupported_response_type"
		}
	}
	return ""
}

// redirectSeparator returns "#" for grants that include a token
// (Implicit/hybrid grants return their parameters in the URL fragment per
// RFC 6749 §4.2.2) and "?" otherwise.
func redirectSeparator(wantToken bool) string {
	if wantToken {
		return "#"
	}
	return "?"
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
