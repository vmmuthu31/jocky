package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DomainFrontConfig holds configuration for CDN-fronted WebSocket connections.
//
// Domain fronting works by establishing a TLS connection to a CDN edge node
// using the SNI of a high-reputation domain (FrontDomain), while the HTTP
// Host header carries the actual backend hostname (RealHost).  The CDN
// routes the request to the real backend based on the Host header.
//
// Example (Cloudflare):
//   FrontDomain = "cloudflare.com"          ← TLS SNI + TCP connect
//   RealHost    = "forensics-gw.ntro.gov.in" ← HTTP Host header
//   BackendURL  = "wss://forensics-gw.ntro.gov.in/telemetry"
type DomainFrontConfig struct {
	// FrontDomain is the high-reputation CDN domain used for TLS SNI and DNS
	// resolution.  The TCP connection goes to FrontDomain:443.
	FrontDomain string `json:"front_domain"`

	// RealHost is placed in the HTTP Host header, routing the request to the
	// actual backend service via the CDN.
	RealHost string `json:"real_host"`

	// BackendURL is the full target WebSocket URL (wss://...).
	// Its host component is replaced with FrontDomain for the dial.
	BackendURL string `json:"backend_url"`

	// Enabled controls whether fronting is active.  When false, the normal
	// direct dial path is used.
	Enabled bool `json:"enabled"`
}

// DomainFrontTransport returns an *http.Transport configured for domain
// fronting.  It dials FrontDomain:443 but presents RealHost in the Host
// header, causing the CDN to route to the actual backend.
//
// The returned transport should be used with an *http.Client or passed
// directly to gorilla/websocket Dial options via the custom dialer path.
func DomainFrontTransport(cfg DomainFrontConfig) (*http.Transport, error) {
	if cfg.FrontDomain == "" {
		return nil, fmt.Errorf("domain_front: FrontDomain must not be empty")
	}
	if cfg.RealHost == "" {
		return nil, fmt.Errorf("domain_front: RealHost must not be empty")
	}

	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// SNI presents FrontDomain — CDN edge terminates TLS
			ServerName: cfg.FrontDomain,
			MinVersion: tls.VersionTLS13,
		},
		// Dial to the CDN edge (FrontDomain), not the real backend host
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Replace any resolved addr with the CDN front domain
			host := cfg.FrontDomain
			if !strings.Contains(host, ":") {
				host = host + ":443"
			}
			return dialer.DialContext(ctx, network, host)
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false, // h2 can break fronting on some CDNs
	}

	return transport, nil
}

// FrontedURL rewrites a wss:// URL so the connection dials through the CDN
// front domain while the real Host header and path are preserved.
//
// Returns (dialURL, hostHeader, error):
//   dialURL    — the URL to pass to the WebSocket dialer (host = FrontDomain)
//   hostHeader — the Host header value to set (= RealHost)
func FrontedURL(cfg DomainFrontConfig) (dialURL string, hostHeader string, err error) {
	if !cfg.Enabled {
		return cfg.BackendURL, "", nil
	}

	parsed, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return "", "", fmt.Errorf("domain_front: invalid BackendURL %q: %w", cfg.BackendURL, err)
	}

	hostHeader = parsed.Host
	if cfg.RealHost != "" {
		hostHeader = cfg.RealHost
	}

	// Replace host in the dial URL with the front domain
	parsed.Host = cfg.FrontDomain
	dialURL = parsed.String()
	return dialURL, hostHeader, nil
}

// FrontedHeader builds the extra HTTP headers needed for a fronted WebSocket
// dial.  The Host header is set to RealHost so the CDN routes correctly.
// An X-Forwarded-Host is added for CDN configs that require it.
func FrontedHeader(cfg DomainFrontConfig) http.Header {
	h := http.Header{}
	if !cfg.Enabled {
		return h
	}
	h.Set("Host", cfg.RealHost)
	h.Set("X-Forwarded-Host", cfg.RealHost)
	// Disguise traffic as a regular browser upgrade request
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	h.Set("Origin", "https://"+cfg.FrontDomain)
	return h
}

// ValidateDomainFrontConfig checks that the config is self-consistent.
func ValidateDomainFrontConfig(cfg DomainFrontConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.FrontDomain == "" {
		return fmt.Errorf("domain_front: FrontDomain required when enabled")
	}
	if cfg.RealHost == "" {
		return fmt.Errorf("domain_front: RealHost required when enabled")
	}
	if cfg.BackendURL == "" {
		return fmt.Errorf("domain_front: BackendURL required when enabled")
	}
	parsed, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return fmt.Errorf("domain_front: invalid BackendURL: %w", err)
	}
	if parsed.Scheme != "wss" && parsed.Scheme != "ws" {
		return fmt.Errorf("domain_front: BackendURL must use ws:// or wss://, got %q", parsed.Scheme)
	}
	return nil
}
