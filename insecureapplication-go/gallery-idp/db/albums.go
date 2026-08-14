package db

import "database/sql"

type Album struct {
	ID          string
	Name        string
	Description string
	UserID      sql.NullString
	CreatedAt   string
	UpdatedAt   string
}

func (d *DB) CreateAlbum(a *Album) error {
	_, err := d.Exec(`INSERT INTO albums (id, name, description, user_id) VALUES (?, ?, ?, ?)`,
		a.ID, a.Name, a.Description, a.UserID)
	return err
}

// GetAlbumByName: albums.name is globally unique across all users (matches
// the original Mongoose schema), so any authenticated user can look up any
// other user's album by guessing/enumerating its name.
func (d *DB) GetAlbumByName(name string) (*Album, error) {
	row := d.QueryRow(`SELECT id, name, description, user_id, created_at, updated_at FROM albums WHERE name = ?`, name)
	a := &Album{}
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.UserID, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (d *DB) ListAlbumsByUser(userID string) ([]*Album, error) {
	rows, err := d.Query(`SELECT id, name, description, user_id, created_at, updated_at FROM albums WHERE user_id = ? ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Album
	for rows.Next() {
		a := &Album{}
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.UserID, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAlbumFields: looked up by name alone, no ownership check (IDOR).
func (d *DB) UpdateAlbumFields(name string, fields map[string]string) error {
	allowed := map[string]bool{"description": true}
	for col, val := range fields {
		if !allowed[col] {
			continue
		}
		if _, err := d.Exec(`UPDATE albums SET `+col+` = ?, updated_at = datetime('now') WHERE name = ?`, val, name); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) DeleteAlbum(name string) error {
	_, err := d.Exec(`DELETE FROM albums WHERE name = ?`, name)
	return err
}
