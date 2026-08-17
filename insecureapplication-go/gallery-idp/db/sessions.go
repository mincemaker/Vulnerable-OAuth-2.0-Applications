package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

const (
	// awaitingLoginTTL bounds how long a stashed pre-login authorization
	// request stays resumable. Past this, a login must not silently pick it
	// back up -- see PendingAuthz.AwaitingLoginValid.
	awaitingLoginTTL = 10 * time.Minute

	// sessionIdleTimeout and sessionAbsoluteTimeout bound an authenticated
	// ("login") session's lifetime -- see GetSession. Values follow OWASP's
	// Session Management Cheat Sheet: idle timeout in the low-risk-app
	// range (15-30 min), absolute timeout for a full day of use (4-8h).
	sessionIdleTimeout     = 30 * time.Minute
	sessionAbsoluteTimeout = 8 * time.Hour
)

// PendingAuthz is the OAuth "authorization in progress" transaction state,
// stashed server-side (keyed by a transaction id) between the GET /authorize
// consent screen and the POST /authorize/decision that completes it.
//
// Deliberately absent: any CSRF token. The only thing that ties a decision
// POST back to its transaction is the transaction_id hidden field, which is
// itself just an opaque id with no binding to the browser that requested it.
type PendingAuthz struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	ResponseType string `json:"response_type"`

	// AwaitingLogin marks an entry that was stashed before the resource
	// owner was authenticated (an unauthenticated GET /authorize), so that
	// POST /login knows to resume the OAuth flow instead of landing on the
	// user's own homepage. It is cleared (left false) once the entry is
	// rewritten for consent-dialog display, and the entry itself is deleted
	// once consumed by an immediate grant or by POST /authorize/decision.
	AwaitingLogin bool `json:"awaiting_login,omitempty"`

	// StashedAt is when this entry was stashed (set only alongside
	// AwaitingLogin). Bounds how long a resume stays valid -- see
	// AwaitingLoginValid.
	StashedAt time.Time `json:"stashed_at,omitzero"`
}

// AwaitingLoginValid reports whether p is a not-yet-expired "stashed before
// login" entry. Both handleAuthorize's resume check and handleLoginSubmit's
// carry-over use this instead of testing AwaitingLogin directly, so the TTL
// is enforced identically at both checkpoints.
func (p PendingAuthz) AwaitingLoginValid() bool {
	return p.AwaitingLogin && !p.StashedAt.IsZero() && time.Since(p.StashedAt) < awaitingLoginTTL
}

type Session struct {
	ID           string
	UserID       sql.NullString
	PendingAuthz map[string]PendingAuthz
}

func (d *DB) CreateSession(id string) error {
	_, err := d.Exec(`INSERT INTO sessions (id) VALUES (?)`, id)
	return err
}

func (d *DB) GetSession(id string) (*Session, error) {
	row := d.QueryRow(`SELECT id, user_id, pending_authz, created_at, updated_at FROM sessions WHERE id = ?`, id)
	s := &Session{}
	var pendingJSON, createdAt, updatedAt string
	err := row.Scan(&s.ID, &s.UserID, &pendingJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Idle/absolute timeout only applies to actual login sessions (non-null
	// user_id) -- see sessionIdleTimeout/sessionAbsoluteTimeout. A pre-login
	// anonymous row is untimed here; only its AwaitingLogin sub-state has
	// its own TTL. A parse failure fails open (treated as not expired)
	// rather than breaking every request.
	if s.UserID.Valid {
		created, createdErr := time.Parse(time.DateTime, createdAt)
		updated, updatedErr := time.Parse(time.DateTime, updatedAt)
		if createdErr == nil && updatedErr == nil {
			now := time.Now()
			if now.Sub(updated) > sessionIdleTimeout || now.Sub(created) > sessionAbsoluteTimeout {
				return nil, nil
			}
		}
	}
	s.PendingAuthz = map[string]PendingAuthz{}
	_ = json.Unmarshal([]byte(pendingJSON), &s.PendingAuthz)
	return s, nil
}

func (d *DB) SetSessionUser(id, userID string) error {
	_, err := d.Exec(`UPDATE sessions SET user_id = ?, updated_at = datetime('now') WHERE id = ?`, userID, id)
	return err
}

func (d *DB) ClearSessionUser(id string) error {
	_, err := d.Exec(`UPDATE sessions SET user_id = NULL, updated_at = datetime('now') WHERE id = ?`, id)
	return err
}

// TouchSession slides a login session's idle-timeout window forward. Called
// from withSession on every request for an authenticated session so ordinary
// activity -- not just writes like SetSessionUser/ClearSessionUser/
// SetPendingAuthz -- keeps the session alive.
func (d *DB) TouchSession(id string) error {
	_, err := d.Exec(`UPDATE sessions SET updated_at = datetime('now') WHERE id = ?`, id)
	return err
}

func (d *DB) SetPendingAuthz(id string, pending map[string]PendingAuthz) error {
	b, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	_, err = d.Exec(`UPDATE sessions SET pending_authz = ?, updated_at = datetime('now') WHERE id = ?`, string(b), id)
	return err
}
