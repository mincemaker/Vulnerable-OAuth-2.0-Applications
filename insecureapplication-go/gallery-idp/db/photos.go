package db

import "database/sql"

type Image struct {
	ID          string
	URL         string
	Description string
	UserID      string
	Album       string
	CreatedAt   string
	UpdatedAt   string
}

func (d *DB) CreateImage(img *Image) error {
	_, err := d.Exec(`INSERT INTO images (id, url, description, user_id, album) VALUES (?, ?, ?, ?, ?)`,
		img.ID, img.URL, img.Description, img.UserID, img.Album)
	return err
}

func (d *DB) GetImage(id string) (*Image, error) {
	row := d.QueryRow(`SELECT id, url, description, user_id, album, created_at, updated_at FROM images WHERE id = ?`, id)
	return scanImage(row)
}

// ListImagesByUser: caller decides whether the requesting identity is
// allowed to see this username's gallery -- see srv/photos.go, which
// (faithfully to the original) does not restrict this to "your own" photos.
func (d *DB) ListImagesByUser(userID string) ([]*Image, error) {
	rows, err := d.Query(`SELECT id, url, description, user_id, album, created_at, updated_at FROM images WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Image
	for rows.Next() {
		img := &Image{}
		if err := rows.Scan(&img.ID, &img.URL, &img.Description, &img.UserID, &img.Album, &img.CreatedAt, &img.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, img)
	}
	return out, rows.Err()
}

// UpdateImageFields: looked up by id alone, no ownership check (IDOR) -- see
// doc/OAuth2_PoC_Verification_Report.md PoC7 for the companion scope bypass.
func (d *DB) UpdateImageFields(id string, fields map[string]string) error {
	allowed := map[string]bool{"description": true, "album": true}
	for col, val := range fields {
		if !allowed[col] {
			continue
		}
		if _, err := d.Exec(`UPDATE images SET `+col+` = ?, updated_at = datetime('now') WHERE id = ?`, val, id); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) DeleteImage(id string) error {
	_, err := d.Exec(`DELETE FROM images WHERE id = ?`, id)
	return err
}

func scanImage(row *sql.Row) (*Image, error) {
	img := &Image{}
	err := row.Scan(&img.ID, &img.URL, &img.Description, &img.UserID, &img.Album, &img.CreatedAt, &img.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return img, nil
}
