package srv

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

const sessionCookieName = "photoprint.sid"

type ctxKey int

const ctxKeySessionID ctxKey = iota

// galleryImage mirrors the shape of one element of gallery-idp's
// GET /photos/me JSON response ({"images":[{"_id":...,"description":...}]}).
type galleryImage struct {
	ID          string `json:"_id"`
	Description string `json:"description"`
}

// sessionData mirrors the two fields the original stores on req.session:
// access_token (app.js /callback) and images (app.js /selectphotos).
type sessionData struct {
	AccessToken string
	Images      []galleryImage
}

// SessionStore is a process-memory session store, deliberately matching
// express-session's default MemoryStore: no persistence, no TTL/pruning,
// data is lost on restart. Unlike gallery-idp (which stores session ids
// unsigned), the cookie value here is HMAC-signed with SESSION_SECRET,
// mirroring express-session + cookie-parser's default signed-cookie
// behavior -- SESSION_SECRET is already wired through docker-compose.yml
// for this app, so this makes actual use of it.
type SessionStore struct {
	mu     sync.Mutex
	data   map[string]*sessionData
	secret []byte
}

func NewSessionStore(secret string) *SessionStore {
	return &SessionStore{data: map[string]*sessionData{}, secret: []byte(secret)}
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *SessionStore) sign(id string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(id))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return id + "." + sig
}

// verify checks the cookie's signature and returns the embedded session id.
func (s *SessionStore) verify(cookieValue string) (string, bool) {
	idx := strings.LastIndex(cookieValue, ".")
	if idx < 0 {
		return "", false
	}
	id := cookieValue[:idx]
	if !hmac.Equal([]byte(s.sign(id)), []byte(cookieValue)) {
		return "", false
	}
	return id, true
}

// withSession ensures every request has a session, cookie present or not --
// matching express-session being mounted unconditionally ahead of every
// route in the original app.js. The cookie has no Secure/SameSite
// hardening, matching express-session's default cookie config.
func (s *SessionStore) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var id string
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if sid, ok := s.verify(c.Value); ok {
				id = sid
			}
		}
		if id == "" {
			id = newSessionID()
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    s.sign(id),
				Path:     "/",
				HttpOnly: true,
			})
		}
		ctx := context.WithValue(r.Context(), ctxKeySessionID, id)
		next(w, r.WithContext(ctx))
	}
}

// get returns (creating if necessary) the session data for the request's
// session id.
func (s *SessionStore) get(r *http.Request) *sessionData {
	id, _ := r.Context().Value(ctxKeySessionID).(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.data[id]
	if !ok {
		d = &sessionData{}
		s.data[id] = d
	}
	return d
}
