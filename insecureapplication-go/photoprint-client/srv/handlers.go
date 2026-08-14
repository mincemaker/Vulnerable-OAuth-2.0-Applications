package srv

import (
	"fmt"
	"net/http"
	"strconv"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "index", nil)
}

// handlePhotoprint is POST /photoprint: builds the authorization request and
// redirects the browser to gallery. Deliberately sends no state parameter
// (see oauth_client.go's buildAuthorizeURL) -- the login-CSRF vulnerability
// documented in doc/OAuth2_PoC_Verification_Report.md PoC1.
func (s *Server) handlePhotoprint(w http.ResponseWriter, r *http.Request) {
	redirectURI := requestProtocol(r) + "://" + r.Host + "/callback"
	authorizeURL := s.buildAuthorizeURL(redirectURI)
	authorizeURL = browserFacingAuthorizeURL(authorizeURL, s.Config.TokenHost, r, s.Config.GalleryBrowserURL)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// handleCallback is GET /callback: exchanges whatever "code" query parameter
// is present for an access token, with no validation that this browser is
// the one that initiated the flow (no state to check). This is the second
// half of the login-CSRF chain: an attacker who gets a victim to open a
// forged /callback?code=... URL has their photoprint session bound to the
// attacker's gallery identity.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	s.Log.Info("code", "code", code) // matches console.log('code: ' + code)

	redirectURI := requestProtocol(r) + "://" + r.Host + "/callback"
	accessToken, err := s.exchangeCode(code, redirectURI)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Access Token Error: %s", err)
		return
	}
	s.Log.Info("token issued", "access_token", accessToken) // matches console.log('Token: ' + ...)

	sess := s.Sessions.get(r)
	sess.AccessToken = accessToken
	http.Redirect(w, r, "/selectphotos", http.StatusFound)
}

// handleSelectPhotos is GET /selectphotos: fetches the caller's photos from
// gallery using the access token as a query parameter (gallery.json's
// documented "/photos/me" path), matching the original's
// GET {tokenHost}/photos/me?access_token=....
func (s *Server) handleSelectPhotos(w http.ResponseWriter, r *http.Request) {
	sess := s.Sessions.get(r)
	images, err := s.fetchMyPhotos(sess.AccessToken)
	if err != nil {
		s.Log.Error("fetching photos failed", "err", err)
		s.renderError(w, http.StatusBadGateway, "Could not load photos from gallery: "+err.Error())
		return
	}
	sess.Images = images
	s.render(w, http.StatusOK, "selectphotos", map[string]any{
		"Images":   images,
		"Basepath": s.Config.TokenHost + "/photos/me/",
	})
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "confirm", nil)
}

// handleOrder is POST /order: mirrors the original's loop over req.body's
// keys (the selectphotos.pug checkboxes are named by array index), pushing
// req.session.images[photo] for each posted key -- including nil when the
// key doesn't resolve to a valid index, and unconditionally accumulating
// totalprice regardless. No ownership/ordering validation, matching the
// original.
func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "bad form submission")
		return
	}
	sess := s.Sessions.get(r)

	const price = 0.10
	var totalPrice float64
	var selected []*galleryImage
	for key := range r.PostForm {
		var pic *galleryImage
		if idx, err := strconv.Atoi(key); err == nil && idx >= 0 && idx < len(sess.Images) {
			pic = &sess.Images[idx]
		}
		selected = append(selected, pic)
		totalPrice += price
	}

	s.render(w, http.StatusOK, "order", map[string]any{
		"SelectedPhotos": selected,
		"Price":          price,
		"TotalPrice":     totalPrice,
		"Basepath":       s.Config.TokenHost + "/photos/me/",
	})
}
