package api

import (
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jocky-sec/jocky/server/models"
	"github.com/jocky-sec/jocky/server/services"
)

type ServerHandler struct {
	sessionSvc *services.SessionService
	warrantSvc *services.WarrantService
}

func NewServerHandler(sessionSvc *services.SessionService, warrantSvc *services.WarrantService) *ServerHandler {
	return &ServerHandler{
		sessionSvc: sessionSvc,
		warrantSvc: warrantSvc,
	}
}

type CreateSessionRequest struct {
	WarrantID string `json:"warrant_id" binding:"required"`
	TargetIP  string `json:"target_ip" binding:"required"`
	AgentID   string `json:"agent_id" binding:"required"`
	DSLSource string `json:"dsl_source" binding:"required"`
	TargetOS  string `json:"target_os" binding:"required"`
	OfficerID string `json:"officer_id" binding:"required"`
}

func (h *ServerHandler) HandleCreateSession(c *gin.Context) {
	var req CreateSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session, err := h.sessionSvc.CreateSession(req.WarrantID, req.TargetIP, req.AgentID, req.DSLSource, req.TargetOS, req.OfficerID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, session)
}

func (h *ServerHandler) HandleListSessions(c *gin.Context) {
	sessions := h.sessionSvc.ListSessions()
	c.JSON(http.StatusOK, gin.H{"sessions": sessions, "count": len(sessions)})
}

func (h *ServerHandler) HandleGetSession(c *gin.Context) {
	id := c.Param("id")
	session, err := h.sessionSvc.GetSession(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}
	c.JSON(http.StatusOK, session)
}

func (h *ServerHandler) HandleListAgents(c *gin.Context) {
	agents := h.sessionSvc.ListAgents()
	c.JSON(http.StatusOK, gin.H{"agents": agents, "count": len(agents)})
}

func (h *ServerHandler) HandleGetAuditLedger(c *gin.Context) {
	ledger := h.sessionSvc.GetAuditLedger()
	c.JSON(http.StatusOK, gin.H{"ledger": ledger, "blocks": len(ledger)})
}

func (h *ServerHandler) HandleValidateWarrant(c *gin.Context) {
	id := c.Query("id")
	warrant, err := h.warrantSvc.ValidateWarrant(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": true, "warrant": warrant})
}

func (h *ServerHandler) HandleRegisterWarrant(c *gin.Context) {
	var warrant models.Warrant
	if err := c.ShouldBindJSON(&warrant); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.warrantSvc.RegisterWarrant(warrant); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "warrant_registered", "id": warrant.ID})
}

func (h *ServerHandler) HandleGetTemplates(c *gin.Context) {
	templates := h.sessionSvc.GetTemplates()
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

func (h *ServerHandler) HandleVerifyEvidence(c *gin.Context) {
	sessionID := c.DefaultQuery("session_id", "ALL")
	result, err := h.sessionSvc.VerifyEvidenceChain(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// HandleCompileDSL — POST /api/v1/compile
// Compiles a JOCKY DSL script to LLVM IR without creating a full session.
// Useful for the dashboard's live editor preview.
func (h *ServerHandler) HandleCompileDSL(c *gin.Context) {
	var req struct {
		DSLSource string `json:"dsl_source" binding:"required"`
		TargetOS  string `json:"target_os" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ir, err := h.sessionSvc.CompileDSLPublic(req.DSLSource, req.TargetOS)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ir":       ir,
		"target":   req.TargetOS,
		"compiled": true,
	})
}

// HandleApproveSession — POST /api/v1/sessions/:id/approve
// Second-officer countersignature under dual-control policy (IT Act Sec 69).
func (h *ServerHandler) HandleApproveSession(c *gin.Context) {
	sessionID := c.Param("id")
	var req struct {
		OfficerID string `json:"officer_id" binding:"required"`
		Notes     string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session, err := h.sessionSvc.ApproveSession(sessionID, req.OfficerID, req.Notes)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "session_approved",
		"session": session,
	})
}

// HandleSubmitEvidenceProto — POST /api/v1/sessions/:id/evidence/proto
// Accepts raw protobuf wire-encoded EvidenceChunk bytes (Content-Type: application/x-protobuf).
func (h *ServerHandler) HandleSubmitEvidenceProto(c *gin.Context) {
	sessionID := c.Param("id")

	body, err := io.ReadAll(c.Request.Body)
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty or unreadable body"})
		return
	}

	chunk, err := services.UnmarshalEvidenceChunk(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "protobuf parse error: " + err.Error()})
		return
	}

	ev := models.EvidenceRecord{
		SessionID:     sessionID,
		ArtifactType:  "proto",
		ChunkIndex:    int(chunk.ChunkIndex),
		TotalChunks:   int(chunk.TotalChunks),
		SHA256Hash:    hex.EncodeToString(chunk.SHA256Checksum),
		EncryptedSize: int64(len(chunk.EncryptedData)),
		ReceivedAt:    time.Now(),
	}

	if err := h.sessionSvc.SubmitEvidence(ev); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status": "evidence_received",
		"chunk":  chunk.ChunkIndex + 1,
		"of":     chunk.TotalChunks,
	})
}

// HandleSubmitEvidence — POST /api/v1/sessions/:id/evidence
// Field agents POST encrypted evidence chunks here.
func (h *ServerHandler) HandleSubmitEvidence(c *gin.Context) {
	sessionID := c.Param("id")

	var ev models.EvidenceRecord
	if err := c.ShouldBindJSON(&ev); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ev.SessionID = sessionID
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = time.Now()
	}

	if err := h.sessionSvc.SubmitEvidence(ev); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":  "evidence_received",
		"chunk":   ev.ChunkIndex + 1,
		"of":      ev.TotalChunks,
		"sha256":  ev.SHA256Hash,
	})
}

