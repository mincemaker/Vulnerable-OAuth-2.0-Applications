// Command photoprint-client runs the deliberately vulnerable OAuth 2.0
// client (relying party) described in
// insecureapplication-go/z-ai/photoprint-client-plan.md. Do not deploy this
// anywhere reachable by untrusted users; it exists to reproduce the PoCs in
// doc/OAuth2_PoC_Verification_Report.md against gallery-idp.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"photoprint-client/srv"
)

func main() {
	listen := flag.String("listen", ":3000", "address to listen on")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := srv.Config{
		ClientID:          envOr("CLIENT_ID", "photoprint"),
		ClientSecret:      envOr("CLIENT_SECRET", "secret"),
		TokenHost:         envOr("GALLERY_URL", "http://gallery:3005"),
		GalleryBrowserURL: os.Getenv("GALLERY_BROWSER_URL"),
		SessionSecret:     envOr("SESSION_SECRET", "changethistoconfigfile"),
		Scope:             "view_gallery",
	}

	tmpl, err := srv.LoadTemplates()
	if err != nil {
		log.Error("could not load templates", "err", err)
		os.Exit(1)
	}

	server := srv.New(cfg, tmpl, log)

	log.Info("photoprint-client listening", "addr", *listen, "gallery", cfg.TokenHost)
	if err := http.ListenAndServe(*listen, server.Handler()); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
