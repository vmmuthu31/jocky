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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jocky-sec/jocky/server/models"
)


type SessionService struct {
	mu           sync.RWMutex
	sessions     map[string]models.ForensicSession
	agents       map[string]models.Agent
	hosts        map[string]models.ForensicHost
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
		hosts: map[string]models.ForensicHost{
			"HOST-001": {Host: "HOST-001", OS: "Windows", Status: "ONLINE", Findings: 12, IPAddress: "192.168.1.10", LastScanID: "JCK-2026-001"},
			"HOST-002": {Host: "HOST-002", OS: "Ubuntu", Status: "ONLINE", Findings: 3, IPAddress: "10.0.5.42", LastScanID: "JCK-2026-002"},
			"HOST-003": {Host: "HOST-003", OS: "Windows", Status: "SCANNING", Findings: 7, IPAddress: "192.168.1.105", LastScanID: "JCK-2026-003"},
			"HOST-004": {Host: "HOST-004", OS: "Ubuntu", Status: "ONLINE", Findings: 0, IPAddress: "10.0.5.99", LastScanID: "JCK-2026-004"},
		},
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
		if runtime.GOOS == "windows" {
			var win []string
			for _, c := range candidates {
				win = append(win, c+".exe")
			}
			candidates = append(win, candidates...)
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
		"investigation": `// JOCKY Forensic Script — Complete Endpoint Analysis

system.processes()
system.services()
system.network_connections()
system.users()
system.persistence()

forensic.collect_logs()
forensic.collect_files()
forensic.generate_report()`,
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

func (s *SessionService) ListHosts() []models.ForensicHost {
	s.mu.RLock()
	defer s.mu.RUnlock()

	order := []string{"HOST-001", "HOST-002", "HOST-003", "HOST-004"}
	var list []models.ForensicHost
	seen := make(map[string]bool)

	for _, k := range order {
		if h, ok := s.hosts[k]; ok {
			list = append(list, h)
			seen[k] = true
		}
	}
	for k, h := range s.hosts {
		if !seen[k] {
			list = append(list, h)
		}
	}
	return list
}

func (s *SessionService) ExecuteHostScan(req models.ScanRequest) (*models.ScanResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	compiler := s.compilerPath
	if compiler == "" {
		candidates := []string{
			"../compiler/target/release/jocky-compile",
			"../compiler/target/debug/jocky-compile",
			"compiler/target/release/jocky-compile",
			"compiler/target/debug/jocky-compile",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				compiler = c
				break
			}
		}
	}
	if compiler == "" {
		return nil, errors.New("jocky-compile binary not found; please build compiler with cargo build --release")
	}

	host := req.Host
	if host == "" {
		host = "WORKSTATION-01"
	}

	scanID := req.ScanID
	if scanID == "" {
		scanID = fmt.Sprintf("JCK-%d-%03d", time.Now().Year(), time.Now().Unix()%1000)
	}

	targetOS := req.OS
	if targetOS == "" {
		if h, ok := s.hosts[host]; ok && h.OS != "" {
			targetOS = h.OS
		} else {
			targetOS = "linux"
		}
	}

	scriptContent := req.Script
	if strings.TrimSpace(scriptContent) == "" {
		scriptContent = `// JOCKY Forensic Script — Complete Endpoint Analysis
system.processes()
system.services()
system.network_connections()
system.users()
system.persistence()

forensic.collect_logs()
forensic.collect_files()
forensic.generate_report()`
	}

	tmpDir, err := os.MkdirTemp("", "jocky_scan_*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	scriptFile := filepath.Join(tmpDir, "scan.jocky")
	if err := os.WriteFile(scriptFile, []byte(scriptContent), 0600); err != nil {
		return nil, err
	}

	reportsDir := "../reports"
	if _, err := os.Stat(reportsDir); err != nil {
		reportsDir = "reports"
		_ = os.MkdirAll(reportsDir, 0755)
	}

	cmd := exec.Command(
		compiler, "run",
		"--target", strings.ToLower(targetOS),
		"--host", host,
		"--scan-id", scanID,
		"--reports-dir", reportsDir,
		scriptFile,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("scan execution failed: %s (output: %s)", err, string(output))
	}

	dateSlug := time.Now().Format("2006-01-02")
	expectedJSON := filepath.Join(reportsDir, fmt.Sprintf("%s-%s.json", host, dateSlug))
	jsonBytes, err := os.ReadFile(expectedJSON)
	if err != nil {
		matches, _ := filepath.Glob(filepath.Join(reportsDir, fmt.Sprintf("%s-*.json", host)))
		if len(matches) > 0 {
			jsonBytes, err = os.ReadFile(matches[len(matches)-1])
		}
	}

	var scanData struct {
		Host             string                  `json:"host"`
		OS               string                  `json:"os"`
		ScanID           string                  `json:"scan_id"`
		Timestamp        string                  `json:"timestamp"`
		EvidenceCount    int                     `json:"evidence_count"`
		ProcessesCount   int                     `json:"processes_count"`
		ServicesCount    int                     `json:"services_count"`
		UsersCount       int                     `json:"users_count"`
		SocketsCount     int                     `json:"sockets_count"`
		PersistenceCount int                     `json:"persistence_count"`
		FilesCount       int                     `json:"files_count"`
		LogsCount        int                     `json:"logs_count"`
		Indicators       []models.SuspiciousItem `json:"indicators"`
		IndicatorSummary struct {
			Total    int `json:"total"`
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		} `json:"indicator_summary"`
		EvidenceSHA256 string `json:"evidence_sha256"`
		JSONReportPath string `json:"json_report_path"`
		HTMLReportPath string `json:"html_report_path"`
	}

	if len(jsonBytes) > 0 {
		_ = json.Unmarshal(jsonBytes, &scanData)
	}

	htmlURL := fmt.Sprintf("/reports/%s-%s.html", host, dateSlug)

	resp := &models.ScanResponse{
		Host:            host,
		OS:              targetOS,
		ScanID:          scanID,
		EvidenceCount:   scanData.EvidenceCount,
		SuspiciousCount: scanData.IndicatorSummary.Total,
		CriticalCount:   scanData.IndicatorSummary.Critical,
		HighCount:       scanData.IndicatorSummary.High,
		MediumCount:     scanData.IndicatorSummary.Medium,
		LowCount:        scanData.IndicatorSummary.Low,
		JSONReportPath:  scanData.JSONReportPath,
		HTMLReportPath:  scanData.HTMLReportPath,
		HTMLReportURL:   htmlURL,
		EvidenceSHA256:  scanData.EvidenceSHA256,
		Indicators:      scanData.Indicators,
	}

	hostEntry, exists := s.hosts[host]
	if !exists {
		hostEntry = models.ForensicHost{Host: host, OS: targetOS, IPAddress: "10.0.5.50"}
	}
	hostEntry.Status = "ONLINE"
	hostEntry.Findings = resp.SuspiciousCount
	hostEntry.LastScanID = scanID
	s.hosts[host] = hostEntry

	officer := req.OfficerID
	if officer == "" {
		officer = "SYSTEM_AUTOMATION"
	}
	s.appendAuditBlock(host, scanID, "FORENSIC_SCAN_COMPLETED", officer, map[string]interface{}{
		"scan_id":         scanID,
		"evidence_count":  resp.EvidenceCount,
		"findings_count":  resp.SuspiciousCount,
		"evidence_sha256": resp.EvidenceSHA256,
		"html_report":     htmlURL,
	})

	return resp, nil
}

func (s *SessionService) ListReports() ([]models.ForensicReportMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reportsDir := "../reports"
	if _, err := os.Stat(reportsDir); err != nil {
		reportsDir = "reports"
	}

	var results []models.ForensicReportMeta
	files, err := filepath.Glob(filepath.Join(reportsDir, "*.json"))
	if err != nil {
		return results, nil
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var parsed struct {
			Host             string `json:"host"`
			ScanID           string `json:"scan_id"`
			EvidenceCount    int    `json:"evidence_count"`
			IndicatorSummary struct {
				Total int `json:"total"`
			} `json:"indicator_summary"`
		}
		if err := json.Unmarshal(data, &parsed); err == nil {
			base := strings.TrimSuffix(filepath.Base(f), ".json")
			results = append(results, models.ForensicReportMeta{
				Host:           parsed.Host,
				ScanID:         parsed.ScanID,
				Timestamp:      time.Now(),
				EvidenceCount:  parsed.EvidenceCount,
				FindingsCount:  parsed.IndicatorSummary.Total,
				HTMLReportURL:  fmt.Sprintf("/reports/%s.html", base),
				JSONReportPath: f,
			})
		}
	}

	return results, nil
}


