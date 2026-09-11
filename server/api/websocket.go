package api

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jocky-sec/jocky/server/models"
	"github.com/jocky-sec/jocky/server/services"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type InboundMessage struct {
	Type          string                 `json:"type"`
	AgentID       string                 `json:"agent_id"`
	Hostname      string                 `json:"hostname,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	OS            string                 `json:"os,omitempty"`
	KernelVersion string                 `json:"kernel_version,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
}

func HandleAgentWebSocket(c *gin.Context, sessionSvc *services.SessionService) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	for {
		var msg InboundMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}

		switch msg.Type {
		case "REGISTER":
			agent := models.Agent{
				ID:            msg.AgentID,
				Hostname:      msg.Hostname,
				IPAddress:     msg.IPAddress,
				OS:            models.OperatingSystem(msg.OS),
				KernelVersion: msg.KernelVersion,
				LastHeartbeat: time.Now(),
				Status:        "ONLINE",
			}
			sessionSvc.RegisterAgent(agent)

			_ = conn.WriteJSON(gin.H{
				"type":   "REGISTER_ACK",
				"status": "APPROVED",
			})

		case "HEARTBEAT":
			agent := models.Agent{
				ID:            msg.AgentID,
				LastHeartbeat: time.Now(),
				Status:        "ONLINE",
			}
			sessionSvc.RegisterAgent(agent)

			_ = conn.WriteJSON(gin.H{
				"type":      "HEARTBEAT_ACK",
				"timestamp": time.Now().Unix(),
			})
		}
	}
}
