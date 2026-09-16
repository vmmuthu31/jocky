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

// createSession is a test helper that POSTs a session and returns the parsed response.
func createSession(t *testing.T, router http.Handler, officerID string) models.ForensicSession {
	t.Helper()
	body := map[string]interface{}{
		"warrant_id": "NTRO-2026-CYBER-0421",
		"target_ip":  "10.0.0.1",
		"agent_id":   "agent-test",
		"dsl_source": `forensic session { target: "10.0.0.1"; warrant: "NTRO-2026-CYBER-0421"; collect { registry: HKLM }; encrypt aes256(key: hsm_derived); transmit via: "wss://test"; }`,
		"target_os":  "windows",
		"officer_id": officerID,
	}
	bodyBytes, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/sessions", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("createSession: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var s models.ForensicSession
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("createSession: parse error: %v", err)
	}
	return s
}

// TestMultiOfficerApproval verifies dual-control approval workflow.
func TestMultiOfficerApproval(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	// Create session as OFFICER-A
	session := createSession(t, router, "OFFICER-A")
	if !session.PendingApproval {
		t.Fatal("new session should be pending approval")
	}
	if session.CreatedByOfficer != "OFFICER-A" {
		t.Fatalf("expected creator OFFICER-A, got %s", session.CreatedByOfficer)
	}

	// OFFICER-A tries to approve their own session — must fail (dual-control)
	selfApprove := map[string]string{"officer_id": "OFFICER-A"}
	selfBytes, _ := json.Marshal(selfApprove)
	wSelf := httptest.NewRecorder()
	reqSelf, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/approve", bytes.NewBuffer(selfBytes))
	reqSelf.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wSelf, reqSelf)
	if wSelf.Code != http.StatusUnprocessableEntity {
		t.Fatalf("self-approval: expected 422, got %d", wSelf.Code)
	}

	// OFFICER-B approves — must succeed
	approve := map[string]string{"officer_id": "OFFICER-B", "notes": "looks good"}
	approveBytes, _ := json.Marshal(approve)
	wApprove := httptest.NewRecorder()
	reqApprove, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/approve", bytes.NewBuffer(approveBytes))
	reqApprove.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wApprove, reqApprove)
	if wApprove.Code != http.StatusOK {
		t.Fatalf("approval by OFFICER-B: expected 200, got %d: %s", wApprove.Code, wApprove.Body.String())
	}

	var approveResp struct {
		Status  string               `json:"status"`
		Session models.ForensicSession `json:"session"`
	}
	if err := json.Unmarshal(wApprove.Body.Bytes(), &approveResp); err != nil {
		t.Fatalf("parse approval response: %v", err)
	}
	if approveResp.Session.Status != models.StatusRunning {
		t.Fatalf("expected session status RUNNING after approval, got %s", approveResp.Session.Status)
	}
	if approveResp.Session.ApprovedByOfficer != "OFFICER-B" {
		t.Fatalf("expected ApprovedByOfficer OFFICER-B, got %s", approveResp.Session.ApprovedByOfficer)
	}
}

// TestDuplicateApprovalRejected ensures a session cannot be approved twice.
func TestDuplicateApprovalRejected(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	session := createSession(t, router, "OFFICER-X")

	approve := map[string]string{"officer_id": "OFFICER-Y"}
	approveBytes, _ := json.Marshal(approve)

	do := func() int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/approve", bytes.NewBuffer(approveBytes))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		return w.Code
	}

	if code := do(); code != http.StatusOK {
		t.Fatalf("first approval: expected 200, got %d", code)
	}
	if code := do(); code != http.StatusUnprocessableEntity {
		t.Fatalf("second approval: expected 422 (already approved), got %d", code)
	}
}

// TestEvidenceSubmission verifies evidence chunks are accepted on an active session.
func TestEvidenceSubmission(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	session := createSession(t, router, "OFFICER-1")

	// Approve first
	approve := map[string]string{"officer_id": "OFFICER-2"}
	approveBytes, _ := json.Marshal(approve)
	wA := httptest.NewRecorder()
	reqA, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/approve", bytes.NewBuffer(approveBytes))
	reqA.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wA, reqA)
	if wA.Code != http.StatusOK {
		t.Fatalf("approval failed: %d", wA.Code)
	}

	// Submit evidence chunk
	ev := map[string]interface{}{
		"artifact_type": "registry",
		"chunk_index":   0,
		"total_chunks":  1,
		"sha256_hash":   "abc123",
		"encrypted_size": 512,
	}
	evBytes, _ := json.Marshal(ev)
	wE := httptest.NewRecorder()
	reqE, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/evidence", bytes.NewBuffer(evBytes))
	reqE.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wE, reqE)
	if wE.Code != http.StatusCreated {
		t.Fatalf("evidence submission: expected 201, got %d: %s", wE.Code, wE.Body.String())
	}

	// Session should now be COMPLETED (single chunk)
	wS := httptest.NewRecorder()
	reqS, _ := http.NewRequest("GET", "/api/v1/sessions/"+session.ID, nil)
	router.ServeHTTP(wS, reqS)
	var completed models.ForensicSession
	json.Unmarshal(wS.Body.Bytes(), &completed)
	if completed.Status != models.StatusCompleted {
		t.Fatalf("expected COMPLETED after final chunk, got %s", completed.Status)
	}
}

// TestEvidenceOnPendingSessionRejected ensures evidence cannot be submitted before approval.
func TestEvidenceOnPendingSessionRejected(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	session := createSession(t, router, "OFFICER-P")

	ev := map[string]interface{}{
		"artifact_type": "memory",
		"chunk_index":   0,
		"total_chunks":  1,
		"sha256_hash":   "deadbeef",
		"encrypted_size": 256,
	}
	evBytes, _ := json.Marshal(ev)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/evidence", bytes.NewBuffer(evBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for evidence on pending session, got %d", w.Code)
	}
}

// TestExpiredWarrantRejected verifies sessions cannot be created with an expired warrant.
func TestExpiredWarrantRejected(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	body := map[string]interface{}{
		"warrant_id": "EXPIRED-WARRANT-0000",
		"target_ip":  "10.0.0.1",
		"agent_id":   "agent-test",
		"dsl_source": `forensic session { target: "10.0.0.1"; warrant: "EXPIRED-WARRANT-0000"; encrypt aes256(key: hsm_derived); transmit via: "wss://test"; }`,
		"target_os":  "linux",
		"officer_id": "OFFICER-Z",
	}
	bodyBytes, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/sessions", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for expired warrant, got %d", w.Code)
	}
}

// TestChainIntegrityAfterEvents verifies the blockchain ledger stays intact after multiple events.
func TestChainIntegrityAfterEvents(t *testing.T) {
	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, "")
	router := SetupRouter(sessionSvc, warrantSvc)

	// Create + approve + submit evidence
	session := createSession(t, router, "OFFICER-C1")

	approveBody, _ := json.Marshal(map[string]string{"officer_id": "OFFICER-C2"})
	wA := httptest.NewRecorder()
	reqA, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/approve", bytes.NewBuffer(approveBody))
	reqA.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wA, reqA)

	evBody, _ := json.Marshal(map[string]interface{}{
		"artifact_type": "disk_mft", "chunk_index": 0, "total_chunks": 1,
		"sha256_hash": "cafebabe", "encrypted_size": 1024,
	})
	wE := httptest.NewRecorder()
	reqE, _ := http.NewRequest("POST", "/api/v1/sessions/"+session.ID+"/evidence", bytes.NewBuffer(evBody))
	reqE.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wE, reqE)

	// Verify chain is still intact
	wV := httptest.NewRecorder()
	reqV, _ := http.NewRequest("GET", "/api/v1/evidence/verify?session_id=ALL", nil)
	router.ServeHTTP(wV, reqV)
	if wV.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d", wV.Code)
	}
	var result models.EvidenceVerificationResult
	json.Unmarshal(wV.Body.Bytes(), &result)
	if !result.ChainIntact {
		t.Fatalf("expected chain intact after events, got: %s", result.Details)
	}
	if result.TotalBlocksChecked < 4 {
		t.Fatalf("expected >=4 blocks (genesis+created+approved+evidence+completed), got %d", result.TotalBlocksChecked)
	}
}

