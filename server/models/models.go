package models

import "time"

type OperatingSystem string

const (
	OSLinux   OperatingSystem = "linux"
	OSWindows OperatingSystem = "windows"
)

type SessionStatus string

const (
	StatusPending   SessionStatus = "PENDING"
	StatusRunning   SessionStatus = "RUNNING"
	StatusCompleted SessionStatus = "COMPLETED"
	StatusFailed    SessionStatus = "FAILED"
	StatusRevoked   SessionStatus = "REVOKED"
)

type Warrant struct {
	ID             string    `json:"id"`
	Jurisdiction   string    `json:"jurisdiction"`
	AuthorizedBy1  string    `json:"authorized_by_1"`
	AuthorizedBy2  string    `json:"authorized_by_2"`
	IssuedAt       time.Time `json:"issued_at"`
	ValidUntil     time.Time `json:"valid_until"`
	SignatureBase64 string   `json:"signature_base64"`
	IsActive       bool      `json:"is_active"`
}

type Agent struct {
	ID             string          `json:"id"`
	Hostname       string          `json:"hostname"`
	IPAddress      string          `json:"ip_address"`
	OS             OperatingSystem `json:"os"`
	KernelVersion  string          `json:"kernel_version"`
	LastHeartbeat  time.Time       `json:"last_heartbeat"`
	Status         string          `json:"status"`
	ActiveSessions int             `json:"active_sessions"`
}

type ForensicSession struct {
	ID                 string        `json:"id"`
	WarrantID          string        `json:"warrant_id"`
	TargetIP           string        `json:"target_ip"`
	AgentID            string        `json:"agent_id"`
	Status             SessionStatus `json:"status"`
	EncryptionAlgo     string        `json:"encryption_algo"`
	KeySource          string        `json:"key_source"`
	TransmitEndpoint   string        `json:"transmit_endpoint"`
	DomainFront        *DomainFrontRef `json:"domain_front,omitempty"`
	DSLSource          string        `json:"dsl_source"`
	CompiledIR         string        `json:"compiled_ir,omitempty"`
	CreatedAt          time.Time     `json:"created_at"`
	CompletedAt        *time.Time    `json:"completed_at,omitempty"`
	// Multi-officer approval fields
	CreatedByOfficer   string        `json:"created_by_officer"`
	ApprovedByOfficer  string        `json:"approved_by_officer,omitempty"`
	ApprovedAt         *time.Time    `json:"approved_at,omitempty"`
	PendingApproval    bool          `json:"pending_approval"`
}

type SessionApproval struct {
	SessionID string `json:"session_id" binding:"required"`
	OfficerID string `json:"officer_id" binding:"required"`
	// Optional notes for audit ledger
	Notes     string `json:"notes"`
}

type EvidenceRecord struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	ArtifactType  string    `json:"artifact_type"`
	ChunkIndex    int       `json:"chunk_index"`
	TotalChunks   int       `json:"total_chunks"`
	SHA256Hash    string    `json:"sha256_hash"`
	EncryptedSize int64     `json:"encrypted_size"`
	ReceivedAt    time.Time `json:"received_at"`
}

type AuditBlock struct {
	Index        int64                  `json:"index"`
	SessionID    string                 `json:"session_id"`
	WarrantID    string                 `json:"warrant_id"`
	EventType    string                 `json:"event_type"`
	OfficerID    string                 `json:"officer_id"`
	Details      map[string]interface{} `json:"details"`
	PrevBlockHash string                `json:"prev_block_hash"`
	BlockHash    string                 `json:"block_hash"`
	Timestamp    time.Time              `json:"timestamp"`
}

type EvidenceVerificationResult struct {
	SessionID         string    `json:"session_id"`
	TotalBlocksChecked int      `json:"total_blocks_checked"`
	ChainIntact        bool     `json:"chain_intact"`
	GenesisHash        string    `json:"genesis_hash"`
	LatestBlockHash    string    `json:"latest_block_hash"`
	ComplianceStandard string    `json:"compliance_standard"`
	VerifiedAt         time.Time `json:"verified_at"`
	Details            string    `json:"details"`
}

// DomainFrontRef is stored on a ForensicSession to describe how the agent
// should route telemetry back through a CDN front domain.
type DomainFrontRef struct {
	FrontDomain string `json:"front_domain"`
	RealHost    string `json:"real_host"`
	Enabled     bool   `json:"enabled"`
}

type ForensicHost struct {
	Host       string `json:"host"`
	OS         string `json:"os"`
	Status     string `json:"status"`
	Findings   int    `json:"findings"`
	IPAddress  string `json:"ip_address"`
	LastScanID string `json:"last_scan_id"`
}

type ScanRequest struct {
	Host      string `json:"host" binding:"required"`
	OS        string `json:"os"`
	Script    string `json:"script"`
	ScanID    string `json:"scan_id"`
	OfficerID string `json:"officer_id"`
}

type SuspiciousItem struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Description  string `json:"description"`
	Evidence     string `json:"evidence"`
	MitreAttckID string `json:"mitre_attck_id"`
}

type ScanResponse struct {
	Host            string           `json:"host"`
	OS              string           `json:"os"`
	ScanID          string           `json:"scan_id"`
	EvidenceCount   int              `json:"evidence_count"`
	SuspiciousCount int              `json:"suspicious_count"`
	CriticalCount   int              `json:"critical_count"`
	HighCount       int              `json:"high_count"`
	MediumCount     int              `json:"medium_count"`
	LowCount        int              `json:"low_count"`
	JSONReportPath  string           `json:"json_report_path"`
	HTMLReportPath  string           `json:"html_report_path"`
	HTMLReportURL   string           `json:"html_report_url"`
	EvidenceSHA256  string           `json:"evidence_sha256"`
	Indicators      []SuspiciousItem `json:"indicators"`
}

type ForensicReportMeta struct {
	Host           string    `json:"host"`
	ScanID         string    `json:"scan_id"`
	Timestamp      time.Time `json:"timestamp"`
	EvidenceCount  int       `json:"evidence_count"`
	FindingsCount  int       `json:"findings_count"`
	HTMLReportURL  string    `json:"html_report_url"`
	JSONReportPath string    `json:"json_report_path"`
}

