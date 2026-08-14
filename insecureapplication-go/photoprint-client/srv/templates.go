package srv

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed templates/*.gohtml
var templatesFS embed.FS

// Templates holds one *template.Template per page, each combining
// templates/layout.gohtml (which defines "layout" and does
// {{template "content" .}}) with that single page's own file (which defines
// "content"). Building one independent set per page avoids every page's
// {{define "content"}} block colliding in a single shared template.Template
// namespace.
type Templates struct {
	pages map[string]*template.Template
}

func LoadTemplates() (*Templates, error) {
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		return nil, fmt.Errorf("read templates dir: %w", err)
	}
	pages := map[string]*template.Template{}
	for _, e := range entries {
		if e.Name() == "layout.gohtml" {
			continue
		}
		t, err := template.New(e.Name()).ParseFS(templatesFS, "templates/layout.gohtml", "templates/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", e.Name(), err)
		}
		pages[strings.TrimSuffix(e.Name(), ".gohtml")] = t
	}
	return &Templates{pages: pages}, nil
}

func (t *Templates) Render(w http.ResponseWriter, status int, page string, data any) error {
	tmpl, ok := t.pages[page]
	if !ok {
		return fmt.Errorf("unknown template %q", page)
	}
	w.WriteHeader(status)
	return tmpl.ExecuteTemplate(w, "layout", data)
}
