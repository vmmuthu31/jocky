package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jocky-sec/jocky/server/models"
)

type SessionService struct {
	mu           sync.RWMutex
	sessions     map[string]models.ForensicSession
	agents       map[string]models.Agent
	auditLedger  []models.AuditBlock
	compilerPath string
	warrantSvc   *WarrantService
	ledgerStore  *LedgerStore
}

func NewSessionService(warrantSvc *WarrantService, compilerPath string) *SessionService {
	return NewSessionServiceWithStore(warrantSvc, compilerPath, NewLedgerStore("."))
}

func NewSessionServiceWithStore(warrantSvc *WarrantService, compilerPath string, store *LedgerStore) *SessionService {
	genesisBlock := models.AuditBlock{
		Index:         0,
		SessionID:     "GENESIS",
		WarrantID:     "GENESIS",
		EventType:     "SYSTEM_INIT",
		OfficerID:     "SYSTEM",
		Details:       map[string]interface{}{"status": "ledger_initialized"},
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		BlockHash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:     time.Now(),
	}

	svc := &SessionService{
		sessions:     make(map[string]models.ForensicSession),
		agents:       make(map[string]models.Agent),
		auditLedger:  []models.AuditBlock{genesisBlock},
		compilerPath: compilerPath,
		warrantSvc:   warrantSvc,
		ledgerStore:  store,
	}

	// Try to load persisted ledger; fall back to genesis block if absent/corrupt
	if store != nil {
		if persisted, err := store.Load(); err == nil && len(persisted) > 0 {
			svc.auditLedger = persisted
		}
	}
	return svc
}

func (s *SessionService) CreateSession(warrantID, targetIP, agentID, dslSource, targetOS string, officerID string) (*models.ForensicSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.warrantSvc.ValidateWarrant(warrantID)
	if err != nil {
		return nil, fmt.Errorf("warrant validation failed: %w", err)
	}

	sessionID := uuid.New().String()

	compiledIR, err := s.compileDSL(dslSource, targetOS)
	if err != nil {
		return nil, fmt.Errorf("compilation failed: %w", err)
	}

	session := models.ForensicSession{
		ID:               sessionID,
		WarrantID:        warrantID,
		TargetIP:         targetIP,
		AgentID:          agentID,
		Status:           models.StatusPending,
		EncryptionAlgo:   "aes256",
		KeySource:        "hsm_derived",
		TransmitEndpoint: "wss://forensics.ntro.gov.in/telemetry",
		DSLSource:        dslSource,
		CompiledIR:       compiledIR,
		CreatedAt:        time.Now(),
	}

	session.CreatedByOfficer = officerID
	session.PendingApproval = true
	s.sessions[sessionID] = session

	s.appendAuditBlock(sessionID, warrantID, "SESSION_CREATED", officerID, map[string]interface{}{
		"target_ip":        targetIP,
		"agent_id":         agentID,
		"target_os":        targetOS,
		"pending_approval": true,
	})

	return &session, nil
}

// ApproveSession allows a second officer to countersign a pending session.
// The approving officer must differ from the session creator.
func (s *SessionService) ApproveSession(sessionID, officerID, notes string) (*models.ForensicSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}
	if !session.PendingApproval {
		return nil, errors.New("session is not awaiting approval")
	}
	if session.CreatedByOfficer == officerID {
		return nil, errors.New("approving officer must differ from creating officer (dual-control policy)")
	}

	now := time.Now()
	session.ApprovedByOfficer = officerID
	session.ApprovedAt = &now
	session.PendingApproval = false
	session.Status = models.StatusRunning
	s.sessions[sessionID] = session

	detail := map[string]interface{}{
		"approving_officer": officerID,
		"creating_officer":  session.CreatedByOfficer,
	}
	if notes != "" {
		detail["notes"] = notes
	}
	s.appendAuditBlock(sessionID, session.WarrantID, "SESSION_APPROVED", officerID, detail)

	return &session, nil
}

// SubmitEvidence records an encrypted evidence chunk from a field agent.
func (s *SessionService) SubmitEvidence(ev models.EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[ev.SessionID]
	if !exists {
		return fmt.Errorf("session '%s' not found", ev.SessionID)
	}
	if session.Status != models.StatusRunning {
		return fmt.Errorf("session '%s' is not active (status: %s)", ev.SessionID, session.Status)
	}

	s.appendAuditBlock(ev.SessionID, session.WarrantID, "EVIDENCE_RECEIVED", "AGENT", map[string]interface{}{
		"artifact_type":  ev.ArtifactType,
		"chunk":          fmt.Sprintf("%d/%d", ev.ChunkIndex+1, ev.TotalChunks),
		"sha256":         ev.SHA256Hash,
		"encrypted_size": ev.EncryptedSize,
	})

	// Mark session completed when final chunk arrives
	if ev.ChunkIndex+1 == ev.TotalChunks {
		now := time.Now()
		session.Status = models.StatusCompleted
		session.CompletedAt = &now
		s.sessions[ev.SessionID] = session
		s.appendAuditBlock(ev.SessionID, session.WarrantID, "SESSION_COMPLETED", "SYSTEM", map[string]interface{}{
			"total_chunks": ev.TotalChunks,
		})
	}
	return nil
}

// CompileDSLPublic exposes the compiler invocation to handlers without creating a session.
func (s *SessionService) CompileDSLPublic(dslSource, targetOS string) (string, error) {
	return s.compileDSL(dslSource, targetOS)
}

func (s *SessionService) compileDSL(dslSource, targetOS string) (string, error) {
	compiler := s.compilerPath
	if compiler == "" {
		candidates := []string{
			"../compiler/target/debug/jocky-compile",
			"../compiler/target/release/jocky-compile",
			"compiler/target/debug/jocky-compile",
			"compiler/target/release/jocky-compile",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				compiler = c
				break
			}
		}
	}

	if compiler == "" {
		return "", fmt.Errorf(
			"jocky-compile binary not found; build the compiler with `cargo build --release` " +
				"in the compiler/ directory and set JOCKY_COMPILER_PATH or pass --compiler",
		)
	}

	tmpDir, err := os.MkdirTemp("", "jocky_compile_*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	inputFile := filepath.Join(tmpDir, "script.jocky")
	outputFile := filepath.Join(tmpDir, "output.ll")

	if err := os.WriteFile(inputFile, []byte(dslSource), 0600); err != nil {
		return "", err
	}

	cmd := exec.Command(compiler, "compile", "--input", inputFile, "--output", outputFile, "--target", targetOS)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compiler error (%s): %s", err, string(output))
	}

	irBytes, err := os.ReadFile(outputFile)
	if err != nil {
		return "", err
	}

	return string(irBytes), nil
}

func (s *SessionService) GetSession(sessionID string) (*models.ForensicSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}
	return &session, nil
}

func (s *SessionService) ListSessions() []models.ForensicSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]models.ForensicSession, 0, len(s.sessions))
	for _, v := range s.sessions {
		list = append(list, v)
	}
	return list
}

func (s *SessionService) RegisterAgent(agent models.Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent.LastHeartbeat = time.Now()
	agent.Status = "ONLINE"
	s.agents[agent.ID] = agent
}

func (s *SessionService) ListAgents() []models.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]models.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		list = append(list, a)
	}
	return list
}

func (s *SessionService) GetAuditLedger() []models.AuditBlock {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return append([]models.AuditBlock(nil), s.auditLedger...)
}

func (s *SessionService) appendAuditBlock(sessionID, warrantID, eventType, officerID string, details map[string]interface{}) {
	prevBlock := s.auditLedger[len(s.auditLedger)-1]
	newIndex := prevBlock.Index + 1
	now := time.Now()

	rawDetails, _ := json.Marshal(details)
	header := fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s:%d",
		newIndex, sessionID, warrantID, eventType, officerID, prevBlock.BlockHash, string(rawDetails), now.Unix())

	hash := sha256.Sum256([]byte(header))
	blockHash := hex.EncodeToString(hash[:])

	block := models.AuditBlock{
		Index:        newIndex,
		SessionID:    sessionID,
		WarrantID:    warrantID,
		EventType:    eventType,
		OfficerID:    officerID,
		Details:      details,
		PrevBlockHash: prevBlock.BlockHash,
		BlockHash:    blockHash,
		Timestamp:    now,
	}

	s.auditLedger = append(s.auditLedger, block)

	// Persist to disk asynchronously so the hot path isn't blocked
	if s.ledgerStore != nil {
		snapshot := append([]models.AuditBlock(nil), s.auditLedger...)
		go func() {
			_ = s.ledgerStore.Save(snapshot)
		}()
	}
}

func (s *SessionService) VerifyEvidenceChain(sessionID string) (*models.EvidenceVerificationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.auditLedger) == 0 {
		return nil, errors.New("audit ledger is uninitialized")
	}

	genesis := s.auditLedger[0]
	latest := s.auditLedger[len(s.auditLedger)-1]

	chainIntact := true
	var failureDetail string

	for i := 1; i < len(s.auditLedger); i++ {
		prev := s.auditLedger[i-1]
		curr := s.auditLedger[i]

		if curr.PrevBlockHash != prev.BlockHash {
			chainIntact = false
			failureDetail = fmt.Sprintf("Hash break between block #%d and #%d", prev.Index, curr.Index)
			break
		}

		rawDetails, _ := json.Marshal(curr.Details)
		header := fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s:%d",
			curr.Index, curr.SessionID, curr.WarrantID, curr.EventType, curr.OfficerID, curr.PrevBlockHash, string(rawDetails), curr.Timestamp.Unix())
		recomputed := sha256.Sum256([]byte(header))
		expectedHash := hex.EncodeToString(recomputed[:])

		if curr.BlockHash != expectedHash {
			chainIntact = false
			failureDetail = fmt.Sprintf("Block #%d payload corrupted; recomputed hash mismatch", curr.Index)
			break
		}
	}

	details := "All audit ledger blocks successfully validated against SHA-256 hash chains. Chain of custody is intact."
	if !chainIntact {
		details = fmt.Sprintf("Chain integrity violation: %s", failureDetail)
	}

	return &models.EvidenceVerificationResult{
		SessionID:          sessionID,
		TotalBlocksChecked: len(s.auditLedger),
		ChainIntact:         chainIntact,
		GenesisHash:         genesis.BlockHash,
		LatestBlockHash:     latest.BlockHash,
		ComplianceStandard:  "Section 65B Indian Evidence Act / ISO/IEC 27037",
		VerifiedAt:          time.Now(),
		Details:             details,
	}, nil
}

// SetDomainFront attaches a CDN domain-fronting config to an existing session.
func (s *SessionService) SetDomainFront(sessionID string, ref *models.DomainFrontRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.sessions[sessionID]
	if !exists {
		return
	}
	session.DomainFront = ref
	s.sessions[sessionID] = session

	s.appendAuditBlock(sessionID, session.WarrantID, "DOMAIN_FRONT_CONFIGURED", "SYSTEM", map[string]interface{}{
		"front_domain": ref.FrontDomain,
		"real_host":    ref.RealHost,
		"enabled":      ref.Enabled,
	})
}

func (s *SessionService) GetTemplates() map[string]string {
	return map[string]string{
		"triage": `// JOCKY Forensic Script — Fast Triage Scan
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    profile: triage;
}`,
		"windows-persistence": `// JOCKY Forensic Script — Windows Persistence & Event Logs
forensic session {
    target: "192.168.1.105";
    warrant: "NTRO-2026-CYBER-0421";
    collect {
        registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,
        disk: mft_scan,
        network: active_connections
    };
    encrypt aes256(key: hsm_derived);
    transmit via: "wss://forensics-gw.ntro.gov.in/telemetry";
}`,
		"linux-ebpf": `// JOCKY Forensic Script — Linux Kernel eBPF Telemetry
forensic session {
    target: "10.0.5.42";
    warrant: "NTRO-2026-LINUX-0089";
    collect {
        proc: all_processes,
        auditd: execve | connect,
        network: active_connections
    };
    encrypt chacha20(key: hsm_derived);
    transmit via: "wss://telemetry-stream.ntro.gov.in/evidence";
}`,
		"pqc-vault": `// JOCKY Forensic Script — Post-Quantum Secure Vault Transmission
forensic session {
    target: "10.100.4.12";
    warrant: "NTRO-2026-INFIL-9901";
    profile: deep_audit;
    encrypt ml_kem(key: hsm_derived);
    transmit via: "wss://pqc-collector.ntro.gov.in/vault";
}`,
	}
}

