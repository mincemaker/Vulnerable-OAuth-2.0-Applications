// Command gallery-idp runs the deliberately vulnerable OAuth 2.0
// authorization server + resource server described in
// insecureapplication-go/z-ai/gallery-idp-plan.md. Do not deploy this
// anywhere reachable by untrusted users; it exists to reproduce the PoCs in
// doc/OAuth2_PoC_Verification_Report.md against a Go/SQLite backend.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"

	"gallery-idp/db"
	"gallery-idp/srv"
)

func browserURL(envVal, listen string) string {
	if envVal != "" {
		return envVal
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen
	}
	if host == "" {
		host = "localhost"
	}
	return "http://" + host + ":" + port
}

func main() {
	listen := flag.String("listen", "127.0.0.1:3005", "address to listen on")
	dbPath := flag.String("db", "./gallery-idp.sqlite3", "path to the sqlite database file")
	uploadsDir := flag.String("uploads", "./public/uploads", "directory for uploaded/served photo files")
	resetDB := flag.Bool("reset-db", false, "delete existing database file before starting")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if *resetDB && *dbPath != "" && *dbPath != ":memory:" {
		if err := os.Remove(*dbPath); err != nil && !os.IsNotExist(err) {
			log.Error("could not reset database", "err", err)
			os.Exit(1)
		}
		log.Info("reset database file", "path", *dbPath)
	}

	if err := os.MkdirAll(*uploadsDir, 0o755); err != nil {
		log.Error("could not create uploads dir", "err", err)
		os.Exit(1)
	}
	if err := db.WriteSeedUploads(*uploadsDir); err != nil {
		log.Error("could not write seed uploads", "err", err)
		os.Exit(1)
	}

	database, err := db.Open(*dbPath)
	if err != nil {
		log.Error("could not open database", "err", err)
		os.Exit(1)
	}
	if err := database.RunMigrations(); err != nil {
		log.Error("could not run migrations", "err", err)
		os.Exit(1)
	}
	if err := database.Seed(); err != nil {
		log.Error("could not seed database", "err", err)
		os.Exit(1)
	}

	tmpl, err := srv.LoadTemplates()
	if err != nil {
		log.Error("could not load templates", "err", err)
		os.Exit(1)
	}

	server := srv.New(database, *uploadsDir, tmpl, log)

	log.Info("gallery-idp listening", "addr", *listen, "db", *dbPath)
	fmt.Println("Open " + browserURL(os.Getenv("GALLERY_BROWSER_URL"), *listen) + " in your browser")
	if err := http.ListenAndServe(*listen, server.Handler()); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}
