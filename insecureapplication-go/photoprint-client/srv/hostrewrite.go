package srv

import (
	"net/http"
	"regexp"
	"strings"
)

// requestProtocol mirrors Express's req.protocol with trust proxy left at
// its default (unset): "https" only when directly TLS-terminated, "http"
// otherwise. The original app.js never calls app.set('trust proxy', ...),
// so X-Forwarded-Proto is deliberately not consulted here either.
func requestProtocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

var (
	leadingPhotoprint = regexp.MustCompile(`^photoprint`)
	trailingPort3000  = regexp.MustCompile(`:3000$`)
)

// browserFacingAuthorizeURL mirrors app.js's POST /photoprint handler: the
// authorize URL is always built against the (container-internal) tokenHost,
// then rewritten to a browser-reachable host so a host-header-driven
// nip.io/localhost demo setup works without hardcoding a public gallery
// hostname.
func browserFacingAuthorizeURL(rawAuthorizeURL, tokenHost string, r *http.Request, galleryBrowserURL string) string {
	if galleryBrowserURL != "" {
		return strings.Replace(rawAuthorizeURL, tokenHost, galleryBrowserURL, 1)
	}
	if !strings.HasPrefix(r.Host, "photoprint:") {
		browserHost := requestProtocol(r) + "://" + rewriteGalleryHost(r.Host)
		return strings.Replace(rawAuthorizeURL, tokenHost, browserHost, 1)
	}
	return rawAuthorizeURL
}

// browserFacingGalleryBase resolves a browser-reachable base URL for gallery from
// either GALLERY_BROWSER_URL or the incoming request's Host header (rewriting
// photoprint:3000 -> gallery:3005 for nip.io/localhost setups), matching
// attacker/app.js's galleryBrowserBase.
func (s *Server) browserFacingGalleryBase(r *http.Request) string {
	if s.Config.GalleryBrowserURL != "" {
		return s.Config.GalleryBrowserURL
	}
	if !strings.HasPrefix(r.Host, "photoprint:") {
		return requestProtocol(r) + "://" + rewriteGalleryHost(r.Host)
	}
	return s.Config.TokenHost
}

// rewriteGalleryHost replicates
// req.get('Host').replace(/^photoprint/, 'gallery').replace(/:3000$/, ':3005').
func rewriteGalleryHost(host string) string {
	host = leadingPhotoprint.ReplaceAllString(host, "gallery")
	host = trailingPort3000.ReplaceAllString(host, ":3005")
	return host
}

