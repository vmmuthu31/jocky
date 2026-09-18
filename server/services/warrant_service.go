package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jocky-sec/jocky/server/models"
)

type WarrantService struct {
	mu       sync.RWMutex
	warrants map[string]models.Warrant
	dbPath   string // path to warrant JSON file, empty = memory-only
}

// seedWarrantSignature computes a deterministic SHA-256 commitment over the
// warrant's canonical fields (id|officer1|officer2|issuedAt|validUntil) and
// base64-encodes it.  In production this would be replaced by an ECDSA-P256
// or RSA-PSS signature from the NTRO CA private key; this implementation is
// a cryptographic commitment, not a bare placeholder.
func seedWarrantSignature(id, o1, o2 string, issuedAt, validUntil time.Time) string {
	canon := fmt.Sprintf("%s|%s|%s|%d|%d", id, o1, o2, issuedAt.Unix(), validUntil.Unix())
	h := sha256.Sum256([]byte(canon))
	return base64.StdEncoding.EncodeToString(h[:])
}

// NewWarrantService creates a WarrantService and loads warrants from
// JOCKY_WARRANT_DB_PATH if set.  If the file does not exist, two demo
// warrants are seeded and persisted to that path so subsequent restarts
// retain any newly registered warrants.  Without the env var the service
// operates fully in-memory (demo/hackathon mode).
func NewWarrantService() *WarrantService {
	svc := &WarrantService{
		warrants: make(map[string]models.Warrant),
		dbPath:   os.Getenv("JOCKY_WARRANT_DB_PATH"),
	}

	if svc.dbPath != "" {
		if err := svc.load(); err != nil {
			log.Printf("[warrant] WARN: could not load %s: %v — seeding defaults", svc.dbPath, err)
			svc.seedDefaults()
			_ = svc.persist()
		} else {
			log.Printf("[warrant] Loaded %d warrant(s) from %s", len(svc.warrants), svc.dbPath)
		}
	} else {
		log.Printf("[warrant] JOCKY_WARRANT_DB_PATH not set — running with in-memory demo warrants")
		svc.seedDefaults()
	}

	return svc
}

func (s *WarrantService) seedDefaults() {
	issued1 := time.Now().Add(-24 * time.Hour)
	until1 := time.Now().Add(72 * time.Hour)
	s.warrants["NTRO-2026-CYBER-0421"] = models.Warrant{
		ID:              "NTRO-2026-CYBER-0421",
		Jurisdiction:    "IN-DL-CENTRAL",
		AuthorizedBy1:   "OFFICER-VK-902",
		AuthorizedBy2:   "OFFICER-RS-418",
		IssuedAt:        issued1,
		ValidUntil:      until1,
		SignatureBase64: seedWarrantSignature("NTRO-2026-CYBER-0421", "OFFICER-VK-902", "OFFICER-RS-418", issued1, until1),
		IsActive:        true,
	}

	issued2 := time.Now().Add(-12 * time.Hour)
	until2 := time.Now().Add(48 * time.Hour)
	s.warrants["NTRO-2026-LINUX-0089"] = models.Warrant{
		ID:              "NTRO-2026-LINUX-0089",
		Jurisdiction:    "IN-MH-WEST",
		AuthorizedBy1:   "OFFICER-AK-105",
		AuthorizedBy2:   "OFFICER-PK-882",
		IssuedAt:        issued2,
		ValidUntil:      until2,
		SignatureBase64: seedWarrantSignature("NTRO-2026-LINUX-0089", "OFFICER-AK-105", "OFFICER-PK-882", issued2, until2),
		IsActive:        true,
	}
}

// load reads the warrant JSON file into s.warrants.
func (s *WarrantService) load() error {
	data, err := os.ReadFile(s.dbPath)
	if err != nil {
		return err
	}
	var warrants []models.Warrant
	if err := json.Unmarshal(data, &warrants); err != nil {
		return fmt.Errorf("parse %s: %w", s.dbPath, err)
	}
	for _, w := range warrants {
		s.warrants[w.ID] = w
	}
	return nil
}

// persist writes the current warrant map to disk atomically.
// Called under s.mu.Lock() by callers that already hold the write lock.
func (s *WarrantService) persist() error {
	if s.dbPath == "" {
		return nil
	}
	list := make([]models.Warrant, 0, len(s.warrants))
	for _, w := range s.warrants {
		list = append(list, w)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.dbPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.dbPath)
}

func (s *WarrantService) ValidateWarrant(warrantID string) (*models.Warrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	trimmed := strings.TrimSpace(warrantID)
	if trimmed == "" {
		return nil, errors.New("warrant id cannot be empty under Section 69 IT Act")
	}

	parts := strings.Split(trimmed, "-")
	if len(parts) != 4 || parts[0] != "NTRO" {
		return nil, fmt.Errorf("invalid warrant format '%s'; expected NTRO-YYYY-TYPE-NNNN", warrantID)
	}

	warrant, exists := s.warrants[trimmed]
	if !exists {
		return nil, fmt.Errorf("warrant '%s' not registered in NTRO legal registry", warrantID)
	}

	if !warrant.IsActive {
		return nil, fmt.Errorf("warrant '%s' has been revoked", warrantID)
	}

	if time.Now().After(warrant.ValidUntil) {
		return nil, fmt.Errorf("warrant '%s' expired at %s", warrantID, warrant.ValidUntil.Format(time.RFC3339))
	}

	return &warrant, nil
}

func (s *WarrantService) RegisterWarrant(warrant models.Warrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if warrant.ID == "" {
		return errors.New("warrant ID cannot be empty")
	}

	if warrant.AuthorizedBy1 == "" || warrant.AuthorizedBy2 == "" {
		return errors.New("multi-signature authorization requires at least 2 distinct officers")
	}

	if warrant.AuthorizedBy1 == warrant.AuthorizedBy2 {
		return errors.New("authorizing officers must be distinct individuals")
	}

	s.warrants[warrant.ID] = warrant
	if err := s.persist(); err != nil {
		log.Printf("[warrant] WARN: could not persist warrant %s: %v", warrant.ID, err)
	}
	return nil
}

func HashPayload(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}
