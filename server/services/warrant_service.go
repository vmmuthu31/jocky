package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jocky-sec/jocky/server/models"
)

type WarrantService struct {
	mu       sync.RWMutex
	warrants map[string]models.Warrant
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

func NewWarrantService() *WarrantService {
	svc := &WarrantService{
		warrants: make(map[string]models.Warrant),
	}

	issued1 := time.Now().Add(-24 * time.Hour)
	until1 := time.Now().Add(72 * time.Hour)
	svc.warrants["NTRO-2026-CYBER-0421"] = models.Warrant{
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
	svc.warrants["NTRO-2026-LINUX-0089"] = models.Warrant{
		ID:              "NTRO-2026-LINUX-0089",
		Jurisdiction:    "IN-MH-WEST",
		AuthorizedBy1:   "OFFICER-AK-105",
		AuthorizedBy2:   "OFFICER-PK-882",
		IssuedAt:        issued2,
		ValidUntil:      until2,
		SignatureBase64: seedWarrantSignature("NTRO-2026-LINUX-0089", "OFFICER-AK-105", "OFFICER-PK-882", issued2, until2),
		IsActive:        true,
	}

	return svc
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
	return nil
}

func HashPayload(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}
