package db

import "database/sql"

type Client struct {
	ClientID     string
	Name         string
	ClientSecret string
	Trusted      bool
	CreatedAt    string
}

// CreateClient stores a client. redirectURI is intentionally accepted but
// discarded -- see the comment on the clients table in 001-init.sql: the
// original Mongoose Client schema has no redirectURIs field either, so a
// self-registered client's declared callback is never actually recorded or
// checked anywhere.
func (d *DB) CreateClient(clientID, name, secret string, trusted bool, redirectURI string) error {
	_, err := d.Exec(`INSERT INTO clients (client_id, name, client_secret, trusted) VALUES (?, ?, ?, ?)`,
		clientID, name, secret, boolToInt(trusted))
	return err
}

func (d *DB) GetClient(clientID string) (*Client, error) {
	row := d.QueryRow(`SELECT client_id, name, client_secret, trusted, created_at FROM clients WHERE client_id = ?`, clientID)
	return scanClient(row)
}

func (d *DB) ListClients() ([]*Client, error) {
	rows, err := d.Query(`SELECT client_id, name, client_secret, trusted, created_at FROM clients ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Client
	for rows.Next() {
		c := &Client{}
		var trusted int
		if err := rows.Scan(&c.ClientID, &c.Name, &c.ClientSecret, &trusted, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.Trusted = trusted != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateClientFields: no ownership/admin check performed by callers (IDOR --
// any logged-in user may edit any client). redirectURIs is accepted upstream
// but never lands in `allowed` since the column doesn't exist.
func (d *DB) UpdateClientFields(clientID string, fields map[string]string) error {
	allowed := map[string]bool{"name": true, "client_secret": true, "trusted": true}
	for col, val := range fields {
		if !allowed[col] {
			continue
		}
		if _, err := d.Exec(`UPDATE clients SET `+col+` = ? WHERE client_id = ?`, val, clientID); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) DeleteClient(clientID string) error {
	_, err := d.Exec(`DELETE FROM clients WHERE client_id = ?`, clientID)
	return err
}

// UpsertClientCredentials rewrites an existing client's id+secret in place,
// used at startup to honor CLIENT_ID/CLIENT_SECRET env overrides for the
// seeded "photoprint" client (mirrors mongo-seed/seed.sh's updateOne upsert).
func (d *DB) UpsertClientCredentials(oldClientID, newClientID, newSecret string) error {
	_, err := d.Exec(`UPDATE clients SET client_id = ?, client_secret = ? WHERE client_id = ?`, newClientID, newSecret, oldClientID)
	return err
}

func scanClient(row *sql.Row) (*Client, error) {
	c := &Client{}
	var trusted int
	err := row.Scan(&c.ClientID, &c.Name, &c.ClientSecret, &trusted, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Trusted = trusted != 0
	return c, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
