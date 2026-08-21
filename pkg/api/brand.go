package api

import (
	_ "embed"
	"strings"
)

// The operator a request arrived for, resolved from the Host header. One binary
// stands behind several hosts, and the page it serves at "/" is the only thing
// a reader sees before signing in, so it names whoever runs that host rather
// than the software. A host with no row here gets the zero value, which renders
// the page with no wordmark and no operator links — correct for anyone running
// this themselves, and the reason adding a row is the whole cost of onboarding
// one.
type brand struct {
	// Name is the wordmark. Empty renders the page unbranded.
	Name string
	// Mark is the operator's logo, as the children of an <svg viewBox="0 0 67 67">.
	Mark string
	// Site and Docs are the footer links. Empty omits the link.
	Site string
	Docs string
	// Ico is the mark as an ICO, for the /favicon.ico a browser asks for on
	// its own whether or not the page names an icon. Empty serves none.
	Ico []byte
}

func (b brand) title() string {
	if b.Name == "" {
		return "MPC"
	}
	return b.Name + " MPC"
}

// The Hanzo mark: five blocks, the same geometry the @hanzo/brand favicon
// carries, so the page and the tab icon are one shape.
const hanzoMark = `<path d="M22.21 67V44.6369H0V67H22.21Z"/>` +
	`<path d="M66.7038 22.3184H22.2534L0.0878906 44.6367H44.4634L66.7038 22.3184Z"/>` +
	`<path d="M22.21 0H0V22.3184H22.21V0Z"/>` +
	`<path d="M66.7198 0H44.5098V22.3184H66.7198V0Z"/>` +
	`<path d="M66.7198 67V44.6369H44.5098V67H66.7198Z"/>`

// Keyed by registered domain — the Host minus its leading label. Only operators
// whose mark is settled belong here; a row with an invented logo is worse than
// no row, because the unbranded page is at least honest about it.
var brands = map[string]brand{
	"hanzo.ai": {
		Name: "Hanzo",
		Mark: hanzoMark,
		Site: "https://hanzo.ai",
		Docs: "https://docs.hanzo.ai",
		Ico:  hanzoIco,
	},
}

// brandFor resolves the operator from an HTTP Host header. It drops the port
// and the leading label ("mpc.hanzo.ai" -> "hanzo.ai"), so every subdomain a
// deployment answers on lands on the same row.
func brandFor(host string) brand {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[i+1:]
	}
	return brands[host]
}

// favicon renders the brand's mark as a standalone SVG document. The fill
// follows the reader's colour scheme because the mark sits on browser chrome we
// do not paint.
func (b brand) favicon() string {
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 67 67" role="img" aria-label="` + b.title() + `">` +
		`<style>path{fill:#000}@media (prefers-color-scheme:dark){path{fill:#fff}}</style>` +
		b.Mark + `</svg>`
}

// Geist is the typeface the page asks for, served from this binary. A
// cross-origin stylesheet is refused by the browser (ERR_BLOCKED_BY_ORB) and
// leaves every reader on system-ui while every rule asks for Geist, so the file
// travels with the server that names it.
//
//go:embed assets/Geist-Variable.woff2
var geistWoff2 []byte

// The same mark as an ICO, byte-for-byte what hanzo.ai serves. A browser asks
// for /favicon.ico on its own even when the page names an SVG, and the ones
// that do not read SVG icons ask for nothing else.
//
//go:embed assets/hanzo.ico
var hanzoIco []byte
