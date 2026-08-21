package api

import (
	"bytes"
	"html/template"
	"net/http"
)

// The page served at "/". It is the only surface a reader meets before they
// hold a token, so everything on it is either true of the software or names the
// operator whose host answered — nothing else. The previous page hard-coded one
// operator's links onto every host, which is how a Lux bridge came to be
// advertised on a Hanzo domain.
var landingTemplate = template.Must(template.New("landing").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — Threshold Signing</title>
<meta name="description" content="Threshold signing over multi-party computation. Key shares never meet, so a full private key never exists anywhere.">
{{if .Mark}}<link rel="icon" type="image/svg+xml" href="/favicon.svg">{{end}}
<style>
@font-face{font-family:Geist;font-style:normal;font-weight:100 900;font-display:swap;src:local('Geist'),url('/fonts/Geist-Variable.woff2') format('woff2')}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Geist,system-ui,sans-serif;background:#000;color:#a1a1a1;-webkit-font-smoothing:antialiased;display:flex;flex-direction:column;min-height:100vh}
a{color:#fff;text-decoration:none}
a:hover{text-decoration:underline}
.wrap{width:100%;max-width:980px;margin:0 auto;padding:0 24px}
header{border-bottom:1px solid #1a1a1a;padding:18px 0}
header .wrap{display:flex;align-items:center;justify-content:space-between;gap:16px}
.brand{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:600;color:#fff;letter-spacing:-.01em}
.brand svg{width:22px;height:22px;fill:#fff}
nav{display:flex;gap:20px;font-size:14px}
nav a{color:#8a8a8a}
nav a:hover{color:#fff;text-decoration:none}
main{flex:1}
.hero{padding:88px 0 56px}
.hero h1{font-size:clamp(34px,6vw,58px);font-weight:600;color:#fff;letter-spacing:-.035em;line-height:1.05}
.hero p{margin-top:18px;max-width:620px;font-size:18px;line-height:1.6}
section{padding:0 0 56px}
h2{font-size:13px;font-weight:500;color:#8a8a8a;text-transform:uppercase;letter-spacing:.08em;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:1px;background:#1a1a1a;border:1px solid #1a1a1a;border-radius:10px;overflow:hidden}
.cell{background:#050505;padding:22px}
.cell h3{color:#fff;font-size:14px;font-weight:600;margin-bottom:6px}
.cell p{font-size:13px;line-height:1.55;color:#7a7a7a}
.chains{display:flex;flex-wrap:wrap;gap:8px}
.chip{border:1px solid #1f1f1f;border-radius:999px;padding:5px 13px;font-size:13px;color:#a1a1a1}
footer{border-top:1px solid #1a1a1a;padding:22px 0}
footer .wrap{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;font-size:13px;color:#7a7a7a}
footer a{color:#7a7a7a}
footer a:hover{color:#fff;text-decoration:none}
</style>
</head>
<body>
<header><div class="wrap">
  <a class="brand" href="/">{{if .Mark}}<svg viewBox="0 0 67 67" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{{.Title}}">{{.Mark}}</svg>{{end}}{{.Title}}</a>
  <nav>
    <a href="#protocols">Protocols</a>
    <a href="#chains">Chains</a>
    {{if .Docs}}<a href="{{.Docs}}">Docs</a>{{end}}
  </nav>
</div></header>

<main>
<div class="hero"><div class="wrap">
  <h1>Signing without<br>a private key.</h1>
  <p>Shares of a key are generated on separate nodes and never leave them. Signatures are produced by a threshold of those nodes together, so the whole key exists at no point in its life — not at setup, not at signing, not in a backup.</p>
</div></div>

<section id="protocols"><div class="wrap">
  <h2>Protocols</h2>
  <div class="grid">
    <div class="cell"><h3>CGGMP21</h3><p>Five-round threshold ECDSA over secp256k1. Bitcoin, Ethereum and every EVM chain.</p></div>
    <div class="cell"><h3>FROST</h3><p>Two-round threshold EdDSA over Ed25519, and BIP-340 Schnorr for Bitcoin Taproot.</p></div>
    <div class="cell"><h3>Resharing</h3><p>The share set is re-drawn without changing the public key, so an operator can leave or join and addresses hold.</p></div>
  </div>
</div></section>

<section id="chains"><div class="wrap">
  <h2>Chains</h2>
  <div class="chains">
    <span class="chip">Bitcoin</span><span class="chip">Ethereum</span><span class="chip">Solana</span>
    <span class="chip">XRPL</span><span class="chip">TON</span><span class="chip">Polygon</span>
    <span class="chip">Arbitrum</span><span class="chip">Base</span><span class="chip">BNB</span>
  </div>
</div></section>
</main>

<footer><div class="wrap">
  <span>{{.Title}}</span>
  <span>
    <a href="/healthz">Status</a>
    {{if .Docs}} &middot; <a href="{{.Docs}}">Docs</a>{{end}}
    {{if .Site}} &middot; <a href="{{.Site}}">{{.Name}}</a>{{end}}
  </span>
</div></footer>
</body>
</html>
`))

// landing renders "/" for whoever the Host names.
func landing(w http.ResponseWriter, r *http.Request) {
	b := brandFor(r.Host)
	var buf bytes.Buffer
	if err := landingTemplate.Execute(&buf, struct {
		brand
		Title string
		Mark  template.HTML
	}{b, b.title(), template.HTML(b.Mark)}); err != nil {
		http.Error(w, "render", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(buf.Bytes())
}

// favicon serves the mark of whoever the Host names. Unbranded hosts have no
// mark, and a 404 is the honest answer for them.
func favicon(w http.ResponseWriter, r *http.Request) {
	b := brandFor(r.Host)
	if b.Mark == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public,max-age=86400")
	_, _ = w.Write([]byte(b.favicon()))
}

func geist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public,max-age=31536000,immutable")
	_, _ = w.Write(geistWoff2)
}
