// Package srv implements the HTTP surface of gallery-idp: a deliberately
// vulnerable OAuth 2.0 authorization server + resource server, ported from
// insecureapplication/gallery (Node.js/Express/oauth2orize/MongoDB) to
// Go/SQLite. See insecureapplication-go/z-ai/gallery-idp-plan.md in the
// parent monorepo for the full design rationale and vulnerability map.
package srv

import (
	"log/slog"
	"net/http"

	"gallery-idp/db"
	"gallery-idp/web"
)

type Server struct {
	DB         *db.DB
	UploadsDir string
	Templates  *Templates
	Log        *slog.Logger
}

func New(database *db.DB, uploadsDir string, tmpl *Templates, log *slog.Logger) *Server {
	return &Server{DB: database, UploadsDir: uploadsDir, Templates: tmpl, Log: log}
}

// registerDual registers the same handler under both path and "/oauth"+path,
// because photoprint calls /oauth/authorize + /oauth/token while attacker
// calls the unprefixed /authorize + /token -- see
// insecureapplication/gallery/routes/index.js, which mounts the oauth router
// at both '/oauth' and '/'.
func registerDual(mux *http.ServeMux, method, path string, h http.HandlerFunc) {
	mux.HandleFunc(method+" "+path, h)
	mux.HandleFunc(method+" /oauth"+path, h)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// --- OAuth 2.0 (mounted at both /oauth/... and /...) ---
	registerDual(mux, "GET", "/authorize", s.withSession(s.handleAuthorize))
	registerDual(mux, "POST", "/authorize/decision", s.withSession(s.requireSession(s.handleDecision)))
	registerDual(mux, "POST", "/token", s.requireClientAuth(s.handleToken))
	mux.HandleFunc("GET /token/introspect", s.handleIntrospect)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleWellKnown)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleWellKnown)

	// --- top-level auth pages ---
	mux.HandleFunc("GET /", s.withSession(s.handleIndex))
	mux.HandleFunc("GET /login", s.withSession(s.handleLoginForm))
	mux.HandleFunc("POST /login", s.withSession(s.handleLoginSubmit))
	mux.HandleFunc("GET /logout", s.withSession(s.handleLogout))
	mux.HandleFunc("POST /logout", s.withSession(s.handleLogout))

	// --- users ---
	mux.HandleFunc("GET /users/register", s.handleRegisterForm)
	mux.HandleFunc("POST /users", s.handleRegisterSubmit)
	mux.HandleFunc("GET /users", s.withSession(s.requireLoggedIn(s.handleUsersList)))
	mux.HandleFunc("GET /users/{name}", s.withSession(s.requireLoggedIn(s.handleUserGet)))
	mux.HandleFunc("PUT /users/{name}", s.withSession(s.requireLoggedIn(s.handleUserUpdate)))
	mux.HandleFunc("POST /users/{name}", s.withSession(s.requireLoggedIn(s.handleUserUpdate)))
	mux.HandleFunc("DELETE /users/{name}", s.withSession(s.requireLoggedIn(s.handleUserDelete)))

	// --- clients (self-service registration: privilege escalation by design) ---
	mux.HandleFunc("POST /clients", s.withSession(s.requireLoggedIn(s.handleClientCreate)))
	mux.HandleFunc("GET /clients", s.withSession(s.requireLoggedIn(s.handleClientsList)))
	mux.HandleFunc("GET /clients/{clientID}", s.withSession(s.requireLoggedIn(s.handleClientGet)))
	mux.HandleFunc("PUT /clients/{clientID}", s.withSession(s.requireLoggedIn(s.handleClientUpdate)))
	mux.HandleFunc("POST /clients/{clientID}", s.withSession(s.requireLoggedIn(s.handleClientUpdate)))
	mux.HandleFunc("DELETE /clients/{clientID}", s.withSession(s.requireLoggedIn(s.handleClientDelete)))

	// --- photos (resource server) ---
	mux.HandleFunc("GET /photos", s.withSession(s.requireSession(s.handleUploadForm)))
	mux.HandleFunc("POST /photos", s.withSession(s.requireSession(s.handleUploadSubmit)))
	mux.HandleFunc("GET /photos/{username}", s.withSession(s.requireLoggedIn(s.handleGallery)))
	// deliberately NO auth middleware on the next three routes (matches the
	// original: metadata + raw image bytes are fully public).
	mux.HandleFunc("GET /photos/{username}/{imageid}/view", s.handleImageMeta)
	mux.HandleFunc("GET /photos/{username}/{imageid}", s.handleImageMeta)
	mux.HandleFunc("GET /photos/{username}/{imageid}/raw", s.handleImageRaw)
	mux.HandleFunc("PUT /photos/{username}/{imageid}", s.withSession(s.requireLoggedIn(s.handleImageUpdate)))
	mux.HandleFunc("DELETE /photos/{username}/{imageid}", s.withSession(s.requireLoggedIn(s.handleImageDelete)))

	// --- albums ---
	mux.HandleFunc("GET /albums", s.withSession(s.requireLoggedIn(s.handleAlbumsList)))
	mux.HandleFunc("GET /albums/{name}", s.withSession(s.requireSession(s.handleAlbumGet)))
	mux.HandleFunc("POST /albums", s.withSession(s.requireSession(s.handleAlbumCreate)))
	mux.HandleFunc("POST /albums/{name}", s.withSession(s.requireSession(s.handleAlbumCreate)))
	mux.HandleFunc("PUT /albums/{name}", s.withSession(s.requireLoggedIn(s.handleAlbumUpdate)))
	mux.HandleFunc("DELETE /albums/{name}", s.withSession(s.requireLoggedIn(s.handleAlbumDelete)))

	// --- static assets: public/ served without auth, matching
	// express.static(public) in the original (uploads/ included). CSS is
	// embedded (see web/embed.go) so the compiled binary is self-contained;
	// uploads/ stays on disk since it's written to at runtime. ---
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(web.Static))))
	mux.Handle("GET /uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(s.UploadsDir))))

	return mux
}
