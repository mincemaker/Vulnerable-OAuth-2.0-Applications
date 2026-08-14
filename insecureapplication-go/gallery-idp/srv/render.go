package srv

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) render(w http.ResponseWriter, status int, page string, data any) {
	if err := s.Templates.Render(w, status, page, data); err != nil {
		s.Log.Error("template render failed", "page", page, "err", err)
	}
}

func (s *Server) renderJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// wantsJSON mirrors the original's res.format({'text/html':..., 'application/json':...}),
// used by most CRUD controllers to serve either an HTML page or a JSON
// representation of the same resource.
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if wantsJSON(r) {
		s.renderJSON(w, status, map[string]string{"error": message})
		return
	}
	s.render(w, status, "error", map[string]string{"Message": message})
}
