package srv

import (
	"net/http"

	"gallery-idp/db"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if u := userFromCtx(r); u != nil {
		http.Redirect(w, r, "/photos/"+u.Username, http.StatusFound)
		return
	}
	s.render(w, http.StatusOK, "index", map[string]any{"User": nil})
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login", map[string]any{"User": userFromCtx(r)})
}

// handleLoginSubmit intentionally fails fast when the username doesn't
// exist, but only fails after a bcrypt comparison when the username exists
// but the password is wrong -- this timing asymmetry allows username
// enumeration, matching a comment in the original
// insecureapplication/gallery/middlewares/auth.js.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	u, err := s.DB.GetUserByUsername(username)
	if err != nil || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sess := sessionFromCtx(r)
	if err := s.DB.SetSessionUser(sess.ID, u.ID); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "session error")
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	_ = s.DB.ClearSessionUser(sess.ID)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "register", map[string]any{"User": nil})
}

// handleRegisterSubmit: on a duplicate username, the error message states
// the username is already taken -- a deliberate user-enumeration vector,
// matching insecureapplication/gallery's registration flow.
func (s *Server) handleRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	if existing, _ := s.DB.GetUserByUsername(username); existing != nil {
		s.renderError(w, r, http.StatusBadRequest, "A user with username \""+username+"\" already exists")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not create user")
		return
	}
	u := &db.User{ID: db.NewID(), Username: username, Name: username, Email: email, PasswordHash: string(hash)}
	if err := s.DB.CreateUser(u); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not create user")
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleUsersList: GET /users, accessible to any logged-in user, not just
// admins -- matches the comment in the original usercontroller.getUsers.
func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not list users")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"users": users})
		return
	}
	s.render(w, http.StatusOK, "users", map[string]any{"User": userFromCtx(r), "Users": users})
}

func resolveUsername(r *http.Request) string {
	name := r.PathValue("name")
	if name == "me" {
		if u := userFromCtx(r); u != nil {
			return u.Username
		}
	}
	return name
}

// handleUserGet: no ownership check -- any logged-in user (or bearer token
// holder) can view any other user's profile by name (IDOR), matching the
// original routes/users.js.
func (s *Server) handleUserGet(w http.ResponseWriter, r *http.Request) {
	u, err := s.DB.GetUserByUsername(resolveUsername(r))
	if err != nil || u == nil {
		s.renderError(w, r, http.StatusNotFound, "user not found")
		return
	}
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"user": u})
		return
	}
	s.render(w, http.StatusOK, "user", map[string]any{"User": userFromCtx(r), "Profile": u})
}

// handleUserUpdate: mass assignment -- whichever of name/email/password
// fields are posted get written, with no check that the caller owns this
// username. Matches Mongoose's `findOneAndUpdate({username}, req.body)` in
// the original usercontroller.updateProfile.
func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := resolveUsername(r)
	fields := map[string]string{}
	if v := r.FormValue("name"); v != "" {
		fields["name"] = v
	}
	if v := r.FormValue("email"); v != "" {
		fields["email"] = v
	}
	if v := r.FormValue("password"); v != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(v), bcrypt.DefaultCost)
		if err == nil {
			fields["password_hash"] = string(hash)
		}
	}
	if err := s.DB.UpdateUserFields(username, fields); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "could not update user")
		return
	}
	u, _ := s.DB.GetUserByUsername(username)
	if wantsJSON(r) {
		s.renderJSON(w, http.StatusOK, map[string]any{"user": u})
		return
	}
	s.render(w, http.StatusOK, "user", map[string]any{"User": userFromCtx(r), "Profile": u})
}

// handleUserDelete: no ownership check (IDOR), matches original.
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.DeleteUser(resolveUsername(r)); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "could not delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
