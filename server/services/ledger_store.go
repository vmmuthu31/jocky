package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/jocky-sec/jocky/server/models"
)

// LedgerStore persists the blockchain audit ledger to a JSON file so the
// chain survives server restarts.  In production this would be a
// WORM-protected storage device or an immutable cloud log service.
type LedgerStore struct {
	mu       sync.RWMutex
	filePath string
}

func NewLedgerStore(dir string) *LedgerStore {
	path := filepath.Join(dir, "jocky_audit_ledger.json")
	return &LedgerStore{filePath: path}
}

// Save writes the full ledger to disk atomically (write-then-rename).
func (s *LedgerStore) Save(ledger []models.AuditBlock) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

// Load reads the ledger from disk.  Returns nil slice (not an error) when the
// file does not yet exist so a fresh genesis block is created instead.
func (s *LedgerStore) Load() ([]models.AuditBlock, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var ledger []models.AuditBlock
	if err := json.Unmarshal(data, &ledger); err != nil {
		return nil, err
	}
	return ledger, nil
}

func (s *LedgerStore) FilePath() string { return s.filePath }
