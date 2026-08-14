package db

import "database/sql"

type User struct {
	ID           string
	Username     string
	Name         string
	Email        string
	PasswordHash string
	CreatedAt    string
	UpdatedAt    string
}

func (d *DB) CreateUser(u *User) error {
	_, err := d.Exec(`INSERT INTO users (id, username, name, email, password_hash) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Name, u.Email, u.PasswordHash)
	return err
}

func (d *DB) GetUserByUsername(username string) (*User, error) {
	row := d.QueryRow(`SELECT id, username, name, email, password_hash, created_at, updated_at FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func (d *DB) GetUserByID(id string) (*User, error) {
	row := d.QueryRow(`SELECT id, username, name, email, password_hash, created_at, updated_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (d *DB) ListUsers() ([]*User, error) {
	rows, err := d.Query(`SELECT id, username, name, email, password_hash, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserFields performs a mass-assignment style update: whichever of
// name/email/password_hash are present in fields get written, with no
// ownership check performed by the caller (see srv/users.go handleUserUpdate).
// This mirrors the original Mongoose `findOneAndUpdate({username}, req.body)`.
func (d *DB) UpdateUserFields(username string, fields map[string]string) error {
	allowed := map[string]bool{"name": true, "email": true, "password_hash": true}
	for col, val := range fields {
		if !allowed[col] {
			continue
		}
		if _, err := d.Exec(`UPDATE users SET `+col+` = ?, updated_at = datetime('now') WHERE username = ?`, val, username); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) DeleteUser(username string) error {
	_, err := d.Exec(`DELETE FROM users WHERE username = ?`, username)
	return err
}

func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}
