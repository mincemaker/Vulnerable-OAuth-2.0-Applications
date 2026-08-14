package db

import (
	"embed"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed seedfiles/*.jpg
var seedFilesFS embed.FS

// WriteSeedUploads extracts the embedded seed photos referenced by
// seedPhotosAndAlbums (7ac9eb7f-...jpg "Kuleuven Bib", ab1dcbf9-...jpg
// "Arenberg Castle") into dir, skipping any file that already exists there.
// This lets the compiled binary bootstrap a fresh uploads directory on its
// own -- without it, a from-scratch uploads dir would have DB rows for
// these two images but no bytes to serve at GET /photos/{u}/{id}/raw.
func WriteSeedUploads(dir string) error {
	entries, err := fs.ReadDir(seedFilesFS, "seedfiles")
	if err != nil {
		return err
	}
	for _, e := range entries {
		dest := filepath.Join(dir, e.Name())
		if _, err := os.Stat(dest); err == nil {
			continue // already present -- don't clobber a user-replaced file
		}
		if err := copySeedFile(dest, "seedfiles/"+e.Name()); err != nil {
			return err
		}
	}
	return nil
}

func copySeedFile(dest, embeddedPath string) (err error) {
	src, err := seedFilesFS.Open(embeddedPath)
	if err != nil {
		return err
	}
	defer src.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()

	_, err = io.Copy(out, src)
	return err
}
