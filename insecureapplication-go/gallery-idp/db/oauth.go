package db

import (
	"database/sql"
)

type AuthCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scope       string
	CreatedAt   string
}

type AccessToken struct {
	Token     string
	ClientID  string
	UserID    sql.NullString
	Scope     sql.NullString
	ExpiresIn int64
	CreatedAt string
}

type RefreshToken struct {
	Token     string
	ClientID  string
	UserID    string
	Scope     sql.NullString
	ExpiresIn int64
	CreatedAt string
}

func (d *DB) CreateAuthCode(code, clientID, userID, redirectURI, scope string) error {
	_, err := d.Exec(`INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope) VALUES (?, ?, ?, ?, ?)`,
		code, clientID, userID, redirectURI, scope)
	return err
}

// GetAuthCode looks a code up by code alone -- deliberately no client_id
// filter (see doc/OAuth2_PoC_Verification_Report.md PoC4: authorization code
// not bound to client). Rows are never deleted after being exchanged (PoC5:
// codes are reusable), and there is no expiry check (no such column exists).
func (d *DB) GetAuthCode(code string) (*AuthCode, error) {
	row := d.QueryRow(`SELECT code, client_id, user_id, redirect_uri, scope, created_at FROM authorization_codes WHERE code = ?`, code)
	c := &AuthCode{}
	var redirectURI, scope sql.NullString
	err := row.Scan(&c.Code, &c.ClientID, &c.UserID, &redirectURI, &scope, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.RedirectURI = redirectURI.String
	c.Scope = scope.String
	return c, nil
}

func (d *DB) CreateAccessToken(token, clientID, userID, scope string) error {
	_, err := d.Exec(`INSERT INTO access_tokens (token, client_id, user_id, scope) VALUES (?, ?, ?, ?)`,
		token, clientID, nullableString(userID), scope)
	return err
}

func (d *DB) GetAccessToken(token string) (*AccessToken, error) {
	row := d.QueryRow(`SELECT token, client_id, user_id, scope, expires_in, created_at FROM access_tokens WHERE token = ?`, token)
	t := &AccessToken{}
	err := row.Scan(&t.Token, &t.ClientID, &t.UserID, &t.Scope, &t.ExpiresIn, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (d *DB) CreateRefreshToken(token, clientID, userID, scope string) error {
	_, err := d.Exec(`INSERT INTO refresh_tokens (token, client_id, user_id, scope) VALUES (?, ?, ?, ?)`,
		token, clientID, userID, scope)
	return err
}

// GetRefreshToken: deliberately no client_id filter (PoC6: refresh token not
// bound to client -- any client that obtains a valid refresh token, by any
// means, can redeem it for a fresh access token inheriting its scope).
func (d *DB) GetRefreshToken(token string) (*RefreshToken, error) {
	row := d.QueryRow(`SELECT token, client_id, user_id, scope, expires_in, created_at FROM refresh_tokens WHERE token = ?`, token)
	t := &RefreshToken{}
	err := row.Scan(&t.Token, &t.ClientID, &t.UserID, &t.Scope, &t.ExpiresIn, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
