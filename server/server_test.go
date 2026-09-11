package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jocky-sec/jocky/server/models"
	"github.com/jocky-sec/jocky/server/services"
)

func TestHealthEndpoint(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}
}

func TestWarrantValidationAPI(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/warrants/validate?id=NTRO-2026-CYBER-0421", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for valid warrant, got %d", w.Code)
	}

	wInvalid := httptest.NewRecorder()
	reqInvalid, _ := http.NewRequest("GET", "/api/v1/warrants/validate?id=INVALID-WARRANT", nil)
	router.ServeHTTP(wInvalid, reqInvalid)

	if wInvalid.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for invalid warrant, got %d", wInvalid.Code)
	}
}

func TestCreateSessionAndAuditLedger(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	body := map[string]interface{}{
		"warrant_id": "NTRO-2026-CYBER-0421",
		"target_ip":  "192.168.1.100",
		"agent_id":   "agent-win-01",
		"dsl_source": `forensic session { target: "192.168.1.100"; warrant: "NTRO-2026-CYBER-0421"; collect { registry: HKLM }; encrypt aes256(key: hsm_derived); transmit via: "wss://endpoint"; }`,
		"target_os":  "windows",
		"officer_id": "OFFICER-007",
	}
	bodyBytes, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/sessions", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected status 201 for session creation, got %d: %s", w.Code, w.Body.String())
	}

	var session models.ForensicSession
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatalf("Failed to parse session response: %v", err)
	}

	if session.WarrantID != "NTRO-2026-CYBER-0421" {
		t.Fatalf("Mismatch in warrant ID: %s", session.WarrantID)
	}

	wLedger := httptest.NewRecorder()
	reqLedger, _ := http.NewRequest("GET", "/api/v1/audit/ledger", nil)
	router.ServeHTTP(wLedger, reqLedger)

	if wLedger.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for ledger, got %d", wLedger.Code)
	}
}

func TestTemplatesEndpoint(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/templates", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for templates, got %d", w.Code)
	}

	var resp struct {
		Templates map[string]string `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse templates response: %v", err)
	}

	if len(resp.Templates) < 3 {
		t.Fatalf("Expected at least 3 templates, got %d", len(resp.Templates))
	}
	if _, ok := resp.Templates["triage"]; !ok {
		t.Fatalf("Expected triage template to exist")
	}
}

func TestEvidenceVerificationAPI(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/evidence/verify?session_id=ALL", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for evidence verify, got %d", w.Code)
	}

	var result models.EvidenceVerificationResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse evidence verification response: %v", err)
	}

	if !result.ChainIntact {
		t.Fatalf("Expected genesis audit ledger chain to be intact")
	}
	if result.TotalBlocksChecked < 1 {
		t.Fatalf("Expected at least 1 block checked (genesis)")
	}
}

