// Package srv implements the HTTP surface of photoprint-client: a
// deliberately vulnerable OAuth 2.0 client (relying party), ported from
// insecureapplication/photoprint (Node.js/Express/simple-oauth2) to Go. See
// insecureapplication-go/z-ai/photoprint-client-plan.md in the parent
// monorepo for the full design rationale.
package srv

import (
	"log/slog"
	"net/http"
	"time"

	"photoprint-client/web"
)

// Config mirrors insecureapplication/photoprint/config/gallery.json plus the
// environment variable overrides app.js reads at startup.
type Config struct {
	ClientID          string
	ClientSecret      string
	TokenHost         string // GALLERY_URL override; default http://localhost:3005 (compose sets it to http://gallery:3005)
	GalleryBrowserURL string // GALLERY_BROWSER_URL override, optional
	SessionSecret     string
	Scope             string
}

type Server struct {
	Config     Config
	Sessions   *SessionStore
	Templates  *Templates
	Log        *slog.Logger
	HTTPClient *http.Client
}

func New(cfg Config, tmpl *Templates, log *slog.Logger) *Server {
	return &Server{
		Config:     cfg,
		Sessions:   NewSessionStore(cfg.SessionSecret),
		Templates:  tmpl,
		Log:        log,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// every route gets a session, matching app.use(expressSession(...)) being
	// applied globally ahead of all routes in the original.
	mux.HandleFunc("GET /", s.Sessions.withSession(s.handleIndex))
	mux.HandleFunc("POST /photoprint", s.Sessions.withSession(s.handlePhotoprint))
	mux.HandleFunc("GET /callback", s.Sessions.withSession(s.handleCallback))
	mux.HandleFunc("GET /selectphotos", s.Sessions.withSession(s.handleSelectPhotos))
	mux.HandleFunc("POST /confirm", s.Sessions.withSession(s.handleConfirm))
	mux.HandleFunc("POST /order", s.Sessions.withSession(s.handleOrder))

	// matches express.static(path.join(__dirname, 'public')) serving
	// public/stylesheets/*.css at the site root. Embedded (see web/embed.go),
	// so the compiled binary is self-contained.
	mux.Handle("GET /stylesheets/", http.FileServer(http.FS(web.Static)))

	// --- API docs (Scalar UI over the embedded OpenAPI spec). ---
	mux.HandleFunc("GET /api-docs", s.handleAPIDocs)
	mux.Handle("GET /api-docs/scalar-standalone.v1.65.1.js",
		http.StripPrefix("/api-docs/", http.FileServer(http.FS(scalarBundleFiles))))

	return mux
}
