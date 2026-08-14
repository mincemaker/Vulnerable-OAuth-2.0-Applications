package srv

import (
	"net/http"
	"time"
)

// handleIntrospect is GET /token/introspect: no authentication required at
// all (matches the original tokeninfo()), and reflects the raw Host header
// into `iss` unsanitized -- see
// insecureapplication/gallery/controllers/oauthcontroller.js's tokeninfo().
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("access_token")
	at, err := s.DB.GetAccessToken(tok)
	if err != nil || at == nil {
		s.renderJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_token"})
		return
	}
	client, err := s.DB.GetClient(at.ClientID)
	if err != nil || client == nil {
		s.renderJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_token"})
		return
	}
	var name string
	if at.UserID.Valid {
		if u, err := s.DB.GetUserByID(at.UserID.String); err == nil && u != nil {
			name = u.Username
		}
	}
	created, _ := time.Parse("2006-01-02 15:04:05", at.CreatedAt)
	iat := created.Unix()
	exp := iat + at.ExpiresIn - time.Now().Unix()

	s.renderJSON(w, http.StatusOK, map[string]any{
		"iss":  r.Host, // insecure: JSON injection via unsanitized Host header, matches original
		"sub":  at.UserID.String,
		"aud":  client.ClientID,
		"azp":  client.ClientID,
		"exp":  exp,
		"iat":  iat,
		"name": name,
	})
}

// handleWellKnown mirrors the original's wellknown(): same field set,
// including the pre-existing bug where authorization_endpoint points at
// /login instead of /authorize, and the same unsanitized Host-header
// reflection into `issuer`.
func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	fullhost := proto + "://" + r.Host // insecure: JSON injection via unsanitized Host header, matches original
	s.renderJSON(w, http.StatusOK, map[string]any{
		"issuer":                                fullhost,
		"token_endpoint":                        fullhost + "/token",
		"introspection_endpoint":                fullhost + "/token/introspect",
		"revocation_endpoint":                   "",
		"authorization_endpoint":                fullhost + "/login",
		"userinfo_endpoint":                     "",
		"registration_endpoint":                 "",
		"jwks_uri":                              "",
		"scopes_supported":                      []string{"profile", "view_gallery", "offline_access"},
		"response_types_supported":              []string{"code", "token", "code token"},
		"response_modes_supported":              []string{"query", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{},
		"acr_values_supported":                  []string{},
		"subject_types_supported":               []string{"public"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claim_types_supported":                 []string{"normal"},
		"claims_supported":                      []string{"sub", "iss", "name"},
		"ui_locales_supported":                  []string{"en"},
		"claims_parameter_supported":            true,
		"request_parameter_supported":           false,
		"request_uri_parameter_supported":       false,
		"require_request_uri_registration":      false,
	})
}
