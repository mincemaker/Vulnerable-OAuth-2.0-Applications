package srv

import (
	"context"
	"net/http"

	"gallery-idp/db"
)

const sessionCookieName = "gallery_sid"

type ctxKey int

const (
	ctxKeySession ctxKey = iota
	ctxKeyUser
	ctxKeyAuthInfo
	ctxKeyClient
)

// AuthInfo carries the scope of the bearer token used for the current
// request, mirroring req.authInfo in the original passport-http-bearer
// strategy. ensureScope() (middleware.go) is the only thing that would ever
// read this, and nothing wires ensureScope() into a route -- see PoC7.
type AuthInfo struct {
	Scope string
}

// withSession is unconditionally applied ahead of every route below it: like
// express-session in the original, every request gets a session row, cookie
// present or not. There is no Secure/SameSite hardening on the cookie
// (matches the original's default express-session cookie config), and the
// session id itself has no CSRF binding to it.
func (s *Server) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sess *db.Session
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			sess, _ = s.DB.GetSession(c.Value)
		}
		if sess == nil {
			id := newOpaqueID()
			if err := s.DB.CreateSession(id); err != nil {
				http.Error(w, "session error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    id,
				Path:     "/",
				HttpOnly: true,
			})
			sess, _ = s.DB.GetSession(id)
		}
		ctx := context.WithValue(r.Context(), ctxKeySession, sess)
		if sess.UserID.Valid {
			if u, err := s.DB.GetUserByID(sess.UserID.String); err == nil && u != nil {
				ctx = context.WithValue(ctx, ctxKeyUser, u)
			}
		}
		next(w, r.WithContext(ctx))
	}
}

func sessionFromCtx(r *http.Request) *db.Session {
	sess, _ := r.Context().Value(ctxKeySession).(*db.Session)
	return sess
}

func userFromCtx(r *http.Request) *db.User {
	u, _ := r.Context().Value(ctxKeyUser).(*db.User)
	return u
}

func authInfoFromCtx(r *http.Request) *AuthInfo {
	a, _ := r.Context().Value(ctxKeyAuthInfo).(*AuthInfo)
	return a
}

func clientFromCtx(r *http.Request) *db.Client {
	c, _ := r.Context().Value(ctxKeyClient).(*db.Client)
	return c
}
