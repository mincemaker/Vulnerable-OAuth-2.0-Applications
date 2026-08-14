package srv

import "net/http"

// handleDecision is POST /authorize/decision (also /oauth/authorize/decision).
// It intentionally ignores the posted `scope` field and re-uses whatever
// scope was stashed server-side when the transaction was created -- this
// matches the original oauth2orize decision() callback, which returns
// {scope: req.oauth2.req.scope} rather than anything from req.body. There is
// no CSRF token check here at all (see insecureapplication/gallery/views/dialog.jade,
// which only posts transaction_id + scope).
func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "bad form")
		return
	}
	txID := r.FormValue("transaction_id")
	sess := sessionFromCtx(r)
	pending, ok := sess.PendingAuthz[txID]
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, "Unknown or expired transaction")
		return
	}
	delete(sess.PendingAuthz, txID)
	if err := s.DB.SetPendingAuthz(sess.ID, sess.PendingAuthz); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "session error")
		return
	}

	if r.FormValue("cancel") != "" {
		noCacheHeaders(w)
		dest := pending.RedirectURI + "?error=access_denied"
		if pending.State != "" {
			dest += "&state=" + pending.State
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}

	client, err := s.DB.GetClient(pending.ClientID)
	if err != nil || client == nil {
		s.renderError(w, r, http.StatusBadRequest, "Unknown client")
		return
	}
	user := userFromCtx(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.grantAndRedirect(w, r, client, user, pending.RedirectURI, pending.Scope, pending.State)
}
