package srv

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
)

// requireSession mirrors connect-ensure-login's login.ensureLoggedIn(): pure
// session-cookie auth, no bearer-token awareness. Used for POST
// /authorize/decision. GET /authorize handles its own unauthenticated case
// (see handleAuthorize) so that it can stash the pending authorization
// request before bouncing to /login, instead of losing it.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userFromCtx(r) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// requireLoggedIn mirrors middlewares/auth.js's ensureLoggedInApi: if the
// request carries a bearer token (query param OR header), authenticate via
// that token ONLY (no session fallback on failure). Otherwise fall back to
// the session cookie. photoprint relies on the query-param form
// (GET /photos/me?access_token=...); the header form is honored too.
func (s *Server) requireLoggedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("access_token")
		authz := r.Header.Get("Authorization")
		if bearer, ok := strings.CutPrefix(authz, "Bearer "); ok && token == "" {
			token = bearer
		}
		if token != "" {
			at, err := s.DB.GetAccessToken(token)
			if err != nil || at == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := r.Context()
			if at.UserID.Valid {
				if u, err := s.DB.GetUserByID(at.UserID.String); err == nil && u != nil {
					ctx = context.WithValue(ctx, ctxKeyUser, u)
				}
			}
			ctx = context.WithValue(ctx, ctxKeyAuthInfo, &AuthInfo{Scope: at.Scope.String})
			next(w, r.WithContext(ctx))
			return
		}
		s.requireSession(next)(w, r)
	}
}

// requireClientAuth mirrors passport-http (Basic) + passport-oauth2-client-password
// (client_secret_post) both being registered for the token endpoint: Basic
// header is checked first, falling back to client_id/client_secret form
// fields (which is what attacker/app.js's /guessauthzcode etc. use).
func (s *Server) requireClientAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		clientID, clientSecret, ok := basicAuth(r)
		if !ok {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}
		client, err := s.DB.GetClient(clientID)
		if err != nil || client == nil || client.ClientSecret != clientSecret {
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyClient, client)
		next(w, r.WithContext(ctx))
	}
}

func basicAuth(r *http.Request) (id, secret string, ok bool) {
	authz := r.Header.Get("Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(authz, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(authz[len(prefix):])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ensureScope mirrors middlewares/auth.js's ensureScope(): defined, and
// intentionally never registered on any route below (see server.go). This is
// PoC7 -- scope is carried on every access token but never enforced by the
// resource server. Kept here, unused, as documentation of that fact.
//
//nolint:unused
func (s *Server) ensureScope(scope string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			info := authInfoFromCtx(r)
			if info == nil || info.Scope == "" {
				next(w, r)
				return
			}
			if info.Scope == "*" || scope == "*" {
				next(w, r)
				return
			}
			for _, sc := range strings.Split(info.Scope, ",") {
				if sc == scope {
					next(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}
