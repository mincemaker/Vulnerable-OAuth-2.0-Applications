package srv

import "net/http"

// handleClientCreate: POST /clients requires only requireLoggedIn -- any
// authenticated user, not just admins, can self-register an arbitrary OAuth
// client (privilege escalation). redirectURIs is accepted but discarded, see
// db/clients.go. Matches routes/clients.js's comment "vulnerability:
// privilege escalation; accessible to all users".
func (s *Server) handleClientCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID := r.FormValue("clientID")
	name := r.FormValue("name")
	secret := r.FormValue("clientSecret")
	redirectURIs := r.FormValue("redirectURIs")
	trusted := r.FormValue("trusted") != ""

	if err := s.DB.CreateClient(clientID, name, secret, trusted, redirectURIs); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not create client")
		return
	}
	c, _ := s.DB.GetClient(clientID)
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"client": c})
		return
	}
	s.render(w, http.StatusOK, "client", map[string]any{"User": userFromCtx(r), "Client": c})
}

// handleClientsList: GET /clients returns every client including its
// plaintext clientSecret, matching clientcontroller.getClients's comment
// "insecure: lists the client secret".
func (s *Server) handleClientsList(w http.ResponseWriter, r *http.Request) {
	clients, err := s.DB.ListClients()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not list clients")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"clients": clients})
		return
	}
	s.render(w, http.StatusOK, "clients", map[string]any{"User": userFromCtx(r), "Clients": clients})
}

// handleClientGet/Update/Delete: looked up by clientID alone, no ownership
// check (IDOR) -- any logged-in user can view/edit/delete any client,
// matching routes/clients.js's "vulnerability: direct object reference".
func (s *Server) handleClientGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.DB.GetClient(r.PathValue("clientID"))
	if err != nil || c == nil {
		s.renderError(w, r, http.StatusNotFound, "client not found")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"client": c})
		return
	}
	s.render(w, http.StatusOK, "client", map[string]any{"User": userFromCtx(r), "Client": c})
}

func (s *Server) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID := r.PathValue("clientID")
	fields := map[string]string{}
	if v := r.FormValue("name"); v != "" {
		fields["name"] = v
	}
	if v := r.FormValue("clientSecret"); v != "" {
		fields["client_secret"] = v
	}
	if r.Form.Has("trusted") {
		fields["trusted"] = boolFormToSQL(r.FormValue("trusted"))
	}
	if err := s.DB.UpdateClientFields(clientID, fields); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not update client")
		return
	}
	c, _ := s.DB.GetClient(clientID)
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"client": c})
		return
	}
	s.render(w, http.StatusOK, "client", map[string]any{"User": userFromCtx(r), "Client": c})
}

func (s *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.DeleteClient(r.PathValue("clientID")); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not delete client")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func boolFormToSQL(v string) string {
	if v == "" || v == "false" || v == "0" {
		return "0"
	}
	return "1"
}
