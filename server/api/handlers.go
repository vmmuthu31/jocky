package api

import (
	"net/http"

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

