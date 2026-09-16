package services

import (
	"testing"
)

func TestFrontedURL_Disabled(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:    false,
		BackendURL: "wss://forensics-gw.ntro.gov.in/telemetry",
	}
	dial, host, err := FrontedURL(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dial != cfg.BackendURL {
		t.Errorf("disabled: dial URL should be unchanged, got %q", dial)
	}
	if host != "" {
		t.Errorf("disabled: hostHeader should be empty, got %q", host)
	}
}

func TestFrontedURL_Enabled(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:     true,
		FrontDomain: "cloudflare.com",
		RealHost:    "forensics-gw.ntro.gov.in",
		BackendURL:  "wss://forensics-gw.ntro.gov.in/telemetry",
	}
	dial, host, err := FrontedURL(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dial != "wss://cloudflare.com/telemetry" {
		t.Errorf("dial URL should use FrontDomain, got %q", dial)
	}
	if host != "forensics-gw.ntro.gov.in" {
		t.Errorf("hostHeader should be RealHost, got %q", host)
	}
}

func TestFrontedURL_InvalidBackend(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:     true,
		FrontDomain: "cloudflare.com",
		RealHost:    "backend.ntro.gov.in",
		BackendURL:  "://not-a-url",
	}
	_, _, err := FrontedURL(cfg)
	if err == nil {
		t.Fatal("expected error for invalid BackendURL")
	}
}

func TestFrontedHeader_SetsHost(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:     true,
		FrontDomain: "cloudflare.com",
		RealHost:    "forensics-gw.ntro.gov.in",
	}
	h := FrontedHeader(cfg)
	if h.Get("Host") != "forensics-gw.ntro.gov.in" {
		t.Errorf("Host header should be RealHost, got %q", h.Get("Host"))
	}
	if h.Get("Origin") != "https://cloudflare.com" {
		t.Errorf("Origin should use FrontDomain, got %q", h.Get("Origin"))
	}
}

func TestFrontedHeader_DisabledIsEmpty(t *testing.T) {
	cfg := DomainFrontConfig{Enabled: false}
	h := FrontedHeader(cfg)
	if len(h) != 0 {
		t.Errorf("disabled fronting should return empty header map, got %v", h)
	}
}

func TestValidateDomainFrontConfig_Valid(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:     true,
		FrontDomain: "cloudflare.com",
		RealHost:    "forensics-gw.ntro.gov.in",
		BackendURL:  "wss://forensics-gw.ntro.gov.in/telemetry",
	}
	if err := ValidateDomainFrontConfig(cfg); err != nil {
		t.Errorf("valid config should pass, got: %v", err)
	}
}

func TestValidateDomainFrontConfig_MissingFront(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:    true,
		RealHost:   "forensics-gw.ntro.gov.in",
		BackendURL: "wss://forensics-gw.ntro.gov.in/telemetry",
	}
	if err := ValidateDomainFrontConfig(cfg); err == nil {
		t.Error("missing FrontDomain should fail validation")
	}
}

func TestValidateDomainFrontConfig_NonWSScheme(t *testing.T) {
	cfg := DomainFrontConfig{
		Enabled:     true,
		FrontDomain: "cloudflare.com",
		RealHost:    "forensics-gw.ntro.gov.in",
		BackendURL:  "https://forensics-gw.ntro.gov.in/telemetry",
	}
	if err := ValidateDomainFrontConfig(cfg); err == nil {
		t.Error("https:// scheme should fail — must be ws:// or wss://")
	}
}

func TestDomainFrontTransport_MissingFront(t *testing.T) {
	cfg := DomainFrontConfig{
		RealHost: "backend.ntro.gov.in",
	}
	_, err := DomainFrontTransport(cfg)
	if err == nil {
		t.Error("empty FrontDomain should return error")
	}
}

func TestDomainFrontTransport_Created(t *testing.T) {
	cfg := DomainFrontConfig{
		FrontDomain: "cloudflare.com",
		RealHost:    "forensics-gw.ntro.gov.in",
	}
	transport, err := DomainFrontTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport == nil {
		t.Error("transport must not be nil")
	}
	if transport.TLSClientConfig == nil {
		t.Error("TLS config must be set")
	}
	if transport.TLSClientConfig.ServerName != "cloudflare.com" {
		t.Errorf("SNI must be FrontDomain, got %q", transport.TLSClientConfig.ServerName)
	}
}
