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
}

func NewSessionService(warrantSvc *WarrantService, compilerPath string) *SessionService {
	genesisBlock := models.AuditBlock{
		Index:        0,
		SessionID:    "GENESIS",
		WarrantID:    "GENESIS",
		EventType:    "SYSTEM_INIT",
		OfficerID:    "SYSTEM",
		Details:      map[string]interface{}{"status": "ledger_initialized"},
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		BlockHash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:    time.Now(),
	}

	return &SessionService{
		sessions:     make(map[string]models.ForensicSession),
		agents:       make(map[string]models.Agent),
		auditLedger:  []models.AuditBlock{genesisBlock},
		compilerPath: compilerPath,
		warrantSvc:   warrantSvc,
	}
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

	s.sessions[sessionID] = session

	s.appendAuditBlock(sessionID, warrantID, "SESSION_CREATED", officerID, map[string]interface{}{
		"target_ip": targetIP,
		"agent_id":  agentID,
		"target_os": targetOS,
	})

	return &session, nil
}

func (s *SessionService) compileDSL(dslSource, targetOS string) (string, error) {
	if s.compilerPath == "" {
		return "; Simulated IR bytecode", nil
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

	cmd := exec.Command(s.compilerPath, "compile", "--input", inputFile, "--output", outputFile, "--target", targetOS)
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
}
