package db

import (
	"database/sql"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// Seed populates the database with the same fixture data the original
// insecureapplication/gallery/mongodbdata/gallery2 BSON dump provided:
// two OAuth clients, one user ("koen"/"password"), two photos, two albums.
// It is idempotent (safe to call on every startup) and, like the original
// mongo-seed container, honors CLIENT_ID/CLIENT_SECRET env vars to rewrite
// the "photoprint" client's credentials in place.
func (d *DB) Seed() error {
	if err := d.seedClients(); err != nil {
		return fmt.Errorf("seed clients: %w", err)
	}
	koenID, err := d.seedUser()
	if err != nil {
		return fmt.Errorf("seed user: %w", err)
	}
	if err := d.seedPhotosAndAlbums(koenID); err != nil {
		return fmt.Errorf("seed photos/albums: %w", err)
	}
	return d.applyClientEnvOverride()
}

func (d *DB) seedClients() error {
	targetID := os.Getenv("CLIENT_ID")
	if targetID == "" {
		targetID = "photoprint"
	}
	existing, err := d.GetClient("photoprint")
	if err != nil {
		return err
	}
	if existing == nil && targetID != "photoprint" {
		existing, err = d.GetClient(targetID)
		if err != nil {
			return err
		}
	}
	if existing == nil {
		if err := d.CreateClient("photoprint", "PhotoPrint", "secret", false, ""); err != nil {
			return err
		}
	}
	existing, err = d.GetClient("maliciousclient")
	if err != nil {
		return err
	}
	if existing == nil {
		if err := d.CreateClient("maliciousclient", "maliciousclient", "secret", false, ""); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) seedUser() (string, error) {
	u, err := d.GetUserByUsername("koen")
	if err != nil {
		return "", err
	}
	if u != nil {
		return u.ID, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	id := NewID()
	if err := d.CreateUser(&User{
		ID:           id,
		Username:     "koen",
		Name:         "koen",
		Email:        "koen@buyens.org",
		PasswordHash: string(hash),
	}); err != nil {
		return "", err
	}
	return id, nil
}

func (d *DB) seedPhotosAndAlbums(userID string) error {
	albums := []struct{ name, desc string }{
		{"Leuven", "Pictures From My University Town"},
		{"default", "Default Album"},
	}
	for _, a := range albums {
		existing, err := d.GetAlbumByName(a.name)
		if err != nil {
			return err
		}
		if existing == nil {
			if err := d.CreateAlbum(&Album{ID: NewID(), Name: a.name, Description: a.desc, UserID: sql.NullString{String: userID, Valid: userID != ""}}); err != nil {
				return err
			}
		}
	}

	images, err := d.ListImagesByUser(userID)
	if err != nil {
		return err
	}
	if len(images) > 0 {
		return nil
	}
	seedImages := []struct{ file, desc string }{
		{"7ac9eb7f-1de1-4c47-819f-f41591035479.jpg", "Kuleuven Bib"},
		{"ab1dcbf9-69cd-4fb9-b9e6-ea3a01f992a0.jpg", "Arenberg Castle"},
	}
	for _, img := range seedImages {
		if err := d.CreateImage(&Image{
			ID:          NewID(),
			URL:         img.file,
			Description: img.desc,
			UserID:      userID,
			Album:       "Leuven",
		}); err != nil {
			return err
		}
	}
	return nil
}

// applyClientEnvOverride mirrors mongo-seed/seed.sh's
// `db.clients.updateOne({clientID:'photoprint'}, {$set:{clientID:$CLIENT_ID, clientSecret:$CLIENT_SECRET}}, {upsert:true})`.
func (d *DB) applyClientEnvOverride() error {
	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		clientID = "photoprint"
	}
	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "secret"
	}
	if clientID == "photoprint" && clientSecret == "secret" {
		return nil // no-op, matches seeded defaults
	}
	existing, err := d.GetClient(clientID)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.ClientSecret != clientSecret {
			return d.UpdateClientFields(clientID, map[string]string{"client_secret": clientSecret})
		}
		return nil
	}
	return d.UpsertClientCredentials("photoprint", clientID, clientSecret)
}
