package srv

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// buildAuthorizeURL mirrors client.authorizationCode.authorizeURL({redirect_uri, scope})
// from simple-oauth2. Deliberately NO state parameter is generated or sent --
// this is photoprint's core vulnerability (login CSRF via the OAuth
// callback, see doc/OAuth2_PoC_Verification_Report.md PoC1).
func (s *Server) buildAuthorizeURL(redirectURI string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", s.Config.ClientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", s.Config.Scope)
	return s.Config.TokenHost + "/oauth/authorize?" + v.Encode()
}

// tokenResponse decodes gallery-idp's POST /token response. access_token is
// deliberately json.Number, not string: the original gallery generates it as
// a JS number and never stringifies it, so it serializes unquoted
// ("access_token":88832). gallery-idp's Go port preserves that asymmetry.
type tokenResponse struct {
	AccessToken json.Number `json:"access_token"`
	Error       string      `json:"error"`
}

// exchangeCode mirrors client.authorizationCode.getToken({code, redirect_uri})
// followed by client.accessToken.create(result): a POST to {tokenHost}/oauth/token
// with grant_type=authorization_code, authenticating with client_id/client_secret
// as form fields (client_secret_post, matching simple-oauth2 v1's default
// bodyFormat, and accepted by gallery-idp's requireClientAuth fallback).
func (s *Server) exchangeCode(code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", s.Config.ClientID)
	form.Set("client_secret", s.Config.ClientSecret)

	req, err := http.NewRequest(http.MethodPost, s.Config.TokenHost+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		if tok.Error != "" {
			return "", fmt.Errorf("access token error: %s", tok.Error)
		}
		return "", fmt.Errorf("access token error: unexpected status %d", resp.StatusCode)
	}
	return tok.AccessToken.String(), nil
}
