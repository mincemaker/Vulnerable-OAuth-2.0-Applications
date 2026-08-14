package srv

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"gallery-idp/db"
)

type imageJSON struct {
	ID          string `json:"_id"`
	Description string `json:"description"`
}

func (s *Server) handleUploadForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "upload", map[string]any{"User": userFromCtx(r)})
}

// handleUploadSubmit: the uploaded file's client-supplied name is used
// verbatim as both the on-disk filename and the stored images.url, with no
// sanitization -- a deliberate path-traversal/overwrite vector, matching
// photoscontroller.uploadImage's use of req.file.originalname.
func (s *Server) handleUploadSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "bad upload")
		return
	}
	file, header, err := r.FormFile("recfile")
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "missing recfile")
		return
	}
	defer file.Close()

	dest := filepath.Join(s.UploadsDir, header.Filename) // vulnerability: no path sanitization
	out, err := os.Create(dest)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not store upload")
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not store upload")
		return
	}

	user := userFromCtx(r)
	img := &db.Image{ID: db.NewID(), URL: header.Filename, Description: r.FormValue("description"), UserID: user.ID, Album: "default"}
	if err := s.DB.CreateImage(img); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not save image record")
		return
	}
	http.Redirect(w, r, "/photos/"+user.Username, http.StatusFound)
}

// handleGallery: GET /photos/{username}, reachable via requireLoggedIn (so
// either a session cookie OR a bearer token works -- photoprint uses
// GET /photos/me?access_token=...). No check that the caller "owns" this
// username; any authenticated identity can list any user's gallery.
func (s *Server) handleGallery(w http.ResponseWriter, r *http.Request) {
	username := resolveGalleryUsername(r)
	target, err := s.DB.GetUserByUsername(username)
	if err != nil || target == nil {
		s.renderError(w, r, http.StatusNotFound, "user not found")
		return
	}
	images, err := s.DB.ListImagesByUser(target.ID)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not list photos")
		return
	}
	if wantsJSON(r) {
		out := make([]imageJSON, 0, len(images))
		for _, img := range images {
			out = append(out, imageJSON{ID: img.ID, Description: img.Description})
		}
		s.renderJSON(w, http.StatusOK, map[string]any{"images": out})
		return
	}
	s.render(w, http.StatusOK, "gallery", map[string]any{"User": userFromCtx(r), "Images": images, "GalleryOwner": username})
}

func resolveGalleryUsername(r *http.Request) string {
	username := r.PathValue("username")
	if username == "me" {
		if u := userFromCtx(r); u != nil {
			return u.Username
		}
	}
	return username
}

// handleImageMeta: GET /photos/{username}/{imageid}[/view], deliberately
// registered with NO auth middleware in server.go -- matches the original,
// where image metadata is fully public regardless of session or token.
func (s *Server) handleImageMeta(w http.ResponseWriter, r *http.Request) {
	img, err := s.DB.GetImage(r.PathValue("imageid"))
	if err != nil || img == nil {
		s.renderError(w, r, http.StatusNotFound, "image not found")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"image": img})
		return
	}
	s.render(w, http.StatusOK, "image", map[string]any{"User": userFromCtx(r), "Image": img})
}

// handleImageRaw: GET /photos/{username}/{imageid}/raw, also registered with
// NO auth middleware -- raw image bytes are fully public. Content-Type is
// hardcoded to "image/*" (not a real MIME type) to match
// controllers/util.js's serveImage, which sets the same literal header value.
func (s *Server) handleImageRaw(w http.ResponseWriter, r *http.Request) {
	img, err := s.DB.GetImage(r.PathValue("imageid"))
	if err != nil || img == nil {
		s.renderError(w, r, http.StatusNotFound, "image not found")
		return
	}
	w.Header().Set("Content-Type", "image/*")
	http.ServeFile(w, r, filepath.Join(s.UploadsDir, img.URL))
}

// handleImageUpdate: PUT /photos/{username}/{imageid}, reached via
// requireLoggedIn. Looked up by imageid alone -- no ownership check (IDOR)
// and no scope check (PoC7: a view_gallery-only access token can still
// perform this write). Responds 204 like the original.
func (s *Server) handleImageUpdate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := r.PathValue("imageid")
	fields := map[string]string{}
	if v := r.FormValue("description"); v != "" {
		fields["description"] = v
	}
	if v := r.FormValue("album"); v != "" {
		fields["album"] = v
	}
	if err := s.DB.UpdateImageFields(id, fields); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not update image")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleImageDelete: same IDOR/scope-bypass characteristics as handleImageUpdate.
func (s *Server) handleImageDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.DeleteImage(r.PathValue("imageid")); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not delete image")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
