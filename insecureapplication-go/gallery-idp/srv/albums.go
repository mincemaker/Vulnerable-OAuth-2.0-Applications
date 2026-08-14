package srv

import (
	"database/sql"
	"net/http"

	"gallery-idp/db"
)

func (s *Server) handleAlbumsList(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	albums, err := s.DB.ListAlbumsByUser(user.ID)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not list albums")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"albums": albums})
		return
	}
	s.render(w, http.StatusOK, "albums", map[string]any{"User": user, "Albums": albums})
}

// handleAlbumGet: album `name` is globally unique (not scoped per user, see
// db/albums.go), so any logged-in user can look up any other user's album by
// name -- matches the original routes/albums.js.
func (s *Server) handleAlbumGet(w http.ResponseWriter, r *http.Request) {
	a, err := s.DB.GetAlbumByName(r.PathValue("name"))
	if err != nil || a == nil {
		s.renderError(w, r, http.StatusNotFound, "album not found")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"album": a})
		return
	}
	s.render(w, http.StatusOK, "album", map[string]any{"User": userFromCtx(r), "Album": a})
}

func (s *Server) handleAlbumCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	user := userFromCtx(r)
	name := r.FormValue("name")
	if name == "" {
		name = r.PathValue("name")
	}
	a := &db.Album{
		ID:          db.NewID(),
		Name:        name,
		Description: r.FormValue("description"),
		UserID:      sql.NullString{String: user.ID, Valid: true},
	}
	if err := s.DB.CreateAlbum(a); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not create album")
		return
	}
	http.Redirect(w, r, "/albums/"+name, http.StatusFound)
}

// handleAlbumUpdate/Delete: looked up by name alone, no ownership check (IDOR).
func (s *Server) handleAlbumUpdate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := r.PathValue("name")
	fields := map[string]string{}
	if v := r.FormValue("description"); v != "" {
		fields["description"] = v
	}
	if err := s.DB.UpdateAlbumFields(name, fields); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not update album")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAlbumDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.DeleteAlbum(r.PathValue("name")); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not delete album")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
