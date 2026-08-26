package agw

import (
	"embed"
	"html/template"
	"io/fs"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed templates
var templateFS embed.FS

// devTemplates enables loading templates from the templates/ directory on
// disk with mtime-based hot reload, so the page can be edited without
// rebuilding. It is switched on by the --dev flag.
var devTemplates atomic.Bool

var templateFuncs = template.FuncMap{
	"join":    strings.Join,
	"has":     stringSliceContains,
	"compact": compactCount,
}

var templateMu sync.Mutex
var templateCache = map[string]*template.Template{}

var devTemplateMu sync.Mutex
var devTemplateCache = map[string]devTemplateEntry{}

type devTemplateEntry struct {
	mod  time.Time
	tmpl *template.Template
}

// getTemplate returns a parsed template. In production it is parsed once from
// the embedded filesystem and cached; in dev mode it is re-parsed from disk
// whenever the file's modification time changes.
func getTemplate(name string) *template.Template {
	if devTemplates.Load() {
		return devTemplate(name)
	}
	templateMu.Lock()
	defer templateMu.Unlock()
	if cached, ok := templateCache[name]; ok {
		return cached
	}
	parsed := parseTemplate(name, templateFS)
	templateCache[name] = parsed
	return parsed
}

func devTemplate(name string) *template.Template {
	path := "templates/" + name
	info, err := os.Stat(path)
	if err != nil {
		// Not running from the repo root: fall back to the embedded copy.
		return parseTemplate(name, templateFS)
	}
	devTemplateMu.Lock()
	defer devTemplateMu.Unlock()
	if cached, ok := devTemplateCache[name]; ok && cached.mod.Equal(info.ModTime()) {
		return cached.tmpl
	}
	parsed := parseTemplate(name, os.DirFS("."))
	devTemplateCache[name] = devTemplateEntry{mod: info.ModTime(), tmpl: parsed}
	return parsed
}

func parseTemplate(name string, files fs.FS) *template.Template {
	return template.Must(template.New(name).Funcs(templateFuncs).ParseFS(files, "templates/"+name))
}
