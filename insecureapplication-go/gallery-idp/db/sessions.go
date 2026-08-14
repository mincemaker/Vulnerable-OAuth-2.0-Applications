package db

import (
	"database/sql"
	"encoding/json"
)

// PendingAuthz is the OAuth "authorization in progress" transaction state,
// stashed server-side (keyed by a transaction id) between the GET /authorize
// consent screen and the POST /authorize/decision that completes it.
//
// Deliberately absent: any CSRF token. The only thing that ties a decision
// POST back to its transaction is the transaction_id hidden field, which is
// itself just an opaque id with no binding to the browser that requested it.
type PendingAuthz struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Scope       string `json:"scope"`
	State       string `json:"state"`
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
	row := d.QueryRow(`SELECT id, user_id, pending_authz FROM sessions WHERE id = ?`, id)
	s := &Session{}
	var pendingJSON string
	err := row.Scan(&s.ID, &s.UserID, &pendingJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
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

func (d *DB) SetPendingAuthz(id string, pending map[string]PendingAuthz) error {
	b, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	_, err = d.Exec(`UPDATE sessions SET pending_authz = ?, updated_at = datetime('now') WHERE id = ?`, string(b), id)
	return err
}
