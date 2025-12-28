package api

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP_IPv4WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	got := clientIP(req)
	if got != "192.168.1.100" {
		t.Errorf("clientIP = %q, want %q", got, "192.168.1.100")
	}
}

func TestClientIP_IPv6WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[::1]:8080"

	got := clientIP(req)
	if got != "::1" {
		t.Errorf("clientIP = %q, want %q", got, "::1")
	}
}

func TestClientIP_IPv6Full(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[2001:db8::1]:443"

	got := clientIP(req)
	if got != "2001:db8::1" {
		t.Errorf("clientIP = %q, want %q", got, "2001:db8::1")
	}
}

func TestClientIP_NoPort(t *testing.T) {
	// net.SplitHostPort fails when there's no port; clientIP falls back to
	// returning RemoteAddr as-is.
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1"

	got := clientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("clientIP = %q, want %q", got, "10.0.0.1")
	}
}

func TestClientIP_IgnoresXForwardedFor(t *testing.T) {
	// clientIP must use RemoteAddr, NOT X-Forwarded-For. The chi RealIP
	// middleware already copies X-Forwarded-For into RemoteAddr before the
	// rate limiter runs. clientIP itself must not re-parse headers — doing
	// so would let attackers spoof their IP and bypass rate limiting.
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 1.1.1.1")

	got := clientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("clientIP = %q, want %q (should ignore X-Forwarded-For)", got, "10.0.0.1")
	}
}

func TestClientIP_IgnoresXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "172.16.0.5:1234"
	req.Header.Set("X-Real-IP", "8.8.8.8")

	got := clientIP(req)
	if got != "172.16.0.5" {
		t.Errorf("clientIP = %q, want %q (should ignore X-Real-IP)", got, "172.16.0.5")
	}
}

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := &RateLimiter{
		limit:      5,
		windowSecs: 60,
	}

	for i := 0; i < 5; i++ {
		if !rl.allow("192.168.1.1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := &RateLimiter{
		limit:      3,
		windowSecs: 60,
	}

	for i := 0; i < 3; i++ {
		rl.allow("192.168.1.1")
	}

	if rl.allow("192.168.1.1") {
		t.Fatal("4th request should be rate limited")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := &RateLimiter{
		limit:      2,
		windowSecs: 60,
	}

	// Exhaust limit for IP A.
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.1")
	if rl.allow("10.0.0.1") {
		t.Fatal("IP A 3rd request should be limited")
	}

	// IP B should still be allowed.
	if !rl.allow("10.0.0.2") {
		t.Fatal("IP B should not be affected by IP A's rate limit")
	}
}
