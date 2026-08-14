package srv

import "net/http"

func (s *Server) render(w http.ResponseWriter, status int, page string, data any) {
	if err := s.Templates.Render(w, status, page, data); err != nil {
		s.Log.Error("template render failed", "page", page, "err", err)
	}
}

func (s *Server) renderError(w http.ResponseWriter, status int, message string) {
	s.render(w, status, "error", map[string]string{"Message": message})
}
