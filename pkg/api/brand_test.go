package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrandForHost(t *testing.T) {
	for _, c := range []struct{ host, want string }{
		{"mpc.hanzo.ai", "Hanzo"},
		{"mpc.hanzo.ai:443", "Hanzo"},
		{"MPC.HANZO.AI", "Hanzo"},
		{"custody.hanzo.ai", "Hanzo"},
		{"mpc.example.com", ""},
		{"localhost:8081", ""},
		{"", ""},
	} {
		if got := brandFor(c.host).Name; got != c.want {
			t.Errorf("brandFor(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// The page a reader sees has to name the operator whose host they typed. Before
// this, one operator's name and links were compiled into every host.
func TestLandingNamesTheHost(t *testing.T) {
	w := httptest.NewRecorder()
	landing(w, httptest.NewRequest("GET", "http://mpc.hanzo.ai/", nil))
	body := w.Body.String()

	for _, want := range []string{
		"<title>Hanzo MPC — Threshold Signing</title>",
		"https://docs.hanzo.ai",
		`href="/favicon.svg"`,
		`href="/favicon.ico"`,
		hanzoMark,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing on mpc.hanzo.ai is missing %q", want)
		}
	}
}

// An operator with no row gets a page that claims nobody, rather than someone
// else's wordmark.
func TestLandingUnbranded(t *testing.T) {
	w := httptest.NewRecorder()
	landing(w, httptest.NewRequest("GET", "http://mpc.example.com/", nil))
	body := w.Body.String()

	if strings.Contains(body, "Hanzo") {
		t.Error("an unknown host is served Hanzo's branding")
	}
	if !strings.Contains(body, "<title>MPC — Threshold Signing</title>") {
		t.Error("an unknown host should get the unbranded title")
	}

	w = httptest.NewRecorder()
	favicon(w, httptest.NewRequest("GET", "http://mpc.example.com/favicon.svg", nil))
	if w.Code != 404 {
		t.Errorf("favicon for an unknown host = %d, want 404", w.Code)
	}
}

// A browser asks for /favicon.ico whether or not the page names an icon, and
// one that does not read SVG icons asks for nothing else.
func TestIcoIsServed(t *testing.T) {
	w := httptest.NewRecorder()
	ico(w, httptest.NewRequest("GET", "http://mpc.hanzo.ai/favicon.ico", nil))

	if w.Code != 200 {
		t.Fatalf("favicon.ico = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "image/x-icon" {
		t.Errorf("Content-Type = %q, want image/x-icon", got)
	}
	// The ICO magic number, so a stub or a truncated embed fails here.
	if b := w.Body.Bytes(); len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 1 || b[3] != 0 {
		t.Error("the body is not an ICO")
	}

	w = httptest.NewRecorder()
	ico(w, httptest.NewRequest("GET", "http://mpc.example.com/favicon.ico", nil))
	if w.Code != 404 {
		t.Errorf("favicon.ico for an unknown host = %d, want 404", w.Code)
	}
}

func TestFaviconIsTheMark(t *testing.T) {
	w := httptest.NewRecorder()
	favicon(w, httptest.NewRequest("GET", "http://mpc.hanzo.ai/favicon.svg", nil))

	if got := w.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Errorf("Content-Type = %q, want image/svg+xml", got)
	}
	if !strings.Contains(w.Body.String(), hanzoMark) {
		t.Error("favicon does not carry the mark")
	}
}

// The page asks for Zen by URL; a URL that 404s leaves every reader on
// system-ui with no sign anything is wrong.
func TestZenIsServed(t *testing.T) {
	w := httptest.NewRecorder()
	zen(w, httptest.NewRequest("GET", "http://mpc.hanzo.ai/fonts/Zen-Variable.woff2", nil))

	if got := w.Header().Get("Content-Type"); got != "font/woff2" {
		t.Errorf("Content-Type = %q, want font/woff2", got)
	}
	if w.Body.Len() == 0 {
		t.Error("the font is empty")
	}
}
