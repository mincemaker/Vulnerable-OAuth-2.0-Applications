package srv

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
)

//go:embed apidocs/openapi.yaml
var openapiYAML string

// scalarBundleFS is @scalar/api-reference@1.65.1's dist/browser/standalone.js,
// vendored unmodified (sha256=4825939e08909061a52f717afd4c2de469433f528cd89407e2c2b2b58cd113ed).
// To upgrade: `npm pack @scalar/api-reference@<version>` in a scratch dir,
// replace this file with the tarball's package/dist/browser/standalone.js,
// and update the filename/comment/route below to match.
//
//go:embed apidocs/scalar-standalone.v1.65.1.js
var scalarBundleFS embed.FS

// scalarBundleFiles roots scalarBundleFS at apidocs/, so it serves
// scalar-standalone.v1.65.1.js directly -- the same
// http.FileServer(http.FS(...)) pattern web.Static uses for CSS (server.go),
// which gets Range and conditional-GET support for free instead of a bespoke
// w.Write of the whole ~3.5MB file on every request.
var scalarBundleFiles = mustSubFS(scalarBundleFS, "apidocs")

func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

const apiDocsPageTemplate = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>photoprint-client API Reference</title>
  <meta name="robots" content="noindex, nofollow" />
</head>
<body>
  <script id="api-reference" type="application/json"
          data-configuration='{"proxyUrl":"","withDefaultFonts":false,"telemetry":false}'>
%s
  </script>
  <script src="/api-docs/scalar-standalone.v1.65.1.js"></script>
</body>
</html>
`

// scriptCloseTag matches </script case-insensitively, matching how the HTML
// tokenizer matches end tags -- a plain strings.ReplaceAll on the lowercase
// form alone would miss "</SCRIPT" or "</Script".
var scriptCloseTag = regexp.MustCompile(`(?i)</script`)

// apiDocsPage is built once: the spec never changes after startup, so there
// is nothing to template per request. The only defensive step is making sure
// a stray "</script" (in any case) inside a YAML description can't truncate
// the tag early.
var apiDocsPage = fmt.Appendf(nil, apiDocsPageTemplate,
	scriptCloseTag.ReplaceAllString(openapiYAML, "<\\/script"))

// apiDocsCSP blocks the vendored Scalar bundle's own outbound calls (its
// "Ask AI" sidebar unconditionally fetches https://api.scalar.com/vector/registry/...
// on mount, independent of the withDefaultFonts/telemetry options set above)
// at the browser level, rather than relying on the bundle's own config
// surface staying trustworthy across upgrades.
const apiDocsCSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'"

func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", apiDocsCSP)
	w.Write(apiDocsPage)
}
