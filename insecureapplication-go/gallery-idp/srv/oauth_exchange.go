package srv

import (
	"encoding/json"
	"net/http"
	"strings"
)

type tokenResponse struct {
	// AccessToken is deliberately json.Number, not string: the original
	// gallery generates it as `Math.floor(Math.random()*...)` (a JS number)
	// and never stringifies it, so it serializes unquoted
	// (`"access_token":88832`). RefreshToken IS stringified in the original
	// (`+ ''`), so it stays a Go string here. This asymmetry is load-bearing
	// for doc/OAuth2_PoC_Verification_Report.md's recorded response bodies.
	AccessToken  json.Number `json:"access_token"`
	RefreshToken *string     `json:"refresh_token,omitempty"`
	TokenType    string      `json:"token_type"`
}

// handleToken is POST /token (also /oauth/token), reached only via
// requireClientAuth. Both grant types below deliberately look codes/tokens
// up with no client_id binding check -- see
// doc/OAuth2_PoC_Verification_Report.md PoC4 (authorization_code) and PoC6
// (refresh_token).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	noCacheHeaders(w)
	_ = r.ParseForm()
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.exchangeAuthorizationCode(w, r)
	case "refresh_token":
		s.exchangeRefreshToken(w, r)
	default:
		s.renderJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (s *Server) exchangeAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	s.Log.Info("authorization code exchange", "code", code) // insecure: logs authorization codes, matches original

	authCode, err := s.DB.GetAuthCode(code)
	if err != nil {
		s.renderJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if authCode == nil {
		s.renderJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied"})
		return
	}

	accessToken := weakToken()
	s.Log.Info("access token issued", "token", accessToken) // insecure: logs access tokens, matches original
	if err := s.DB.CreateAccessToken(accessToken, authCode.ClientID, authCode.UserID, authCode.Scope); err != nil {
		s.renderJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	resp := tokenResponse{AccessToken: json.Number(accessToken), TokenType: "Bearer"}
	if strings.Contains(authCode.Scope, "offline_access") {
		refreshToken := weakToken()
		if err := s.DB.CreateRefreshToken(refreshToken, authCode.ClientID, authCode.UserID, authCode.Scope); err != nil {
			s.renderJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		resp.RefreshToken = &refreshToken
	}
	s.renderJSON(w, http.StatusOK, resp)
}

func (s *Server) exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	tok := r.FormValue("refresh_token")
	s.Log.Info("refresh token exchange", "token", tok) // insecure: logs refresh tokens, matches original

	rt, err := s.DB.GetRefreshToken(tok)
	if err != nil {
		s.renderJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if rt == nil {
		s.renderJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied"})
		return
	}

	accessToken := weakToken()
	// insecure: the new access token inherits whatever scope the refresh
	// token carried, regardless of which client is redeeming it.
	if err := s.DB.CreateAccessToken(accessToken, rt.ClientID, rt.UserID, rt.Scope.String); err != nil {
		s.renderJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.renderJSON(w, http.StatusOK, tokenResponse{AccessToken: json.Number(accessToken), TokenType: "Bearer"})
}
