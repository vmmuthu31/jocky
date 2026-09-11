package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jocky-sec/jocky/server/api"
	"github.com/jocky-sec/jocky/server/services"
)

func SetupRouter(sessionSvc *services.SessionService, warrantSvc *services.WarrantService) *gin.Engine {
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	handler := api.NewServerHandler(sessionSvc, warrantSvc)

	v1 := r.Group("/api/v1")
	{
		v1.POST("/sessions", handler.HandleCreateSession)
		v1.GET("/sessions", handler.HandleListSessions)
		v1.GET("/sessions/:id", handler.HandleGetSession)

		v1.GET("/agents", handler.HandleListAgents)

		v1.GET("/warrants/validate", handler.HandleValidateWarrant)
		v1.POST("/warrants", handler.HandleRegisterWarrant)

		v1.GET("/audit/ledger", handler.HandleGetAuditLedger)
		v1.GET("/evidence/verify", handler.HandleVerifyEvidence)

		v1.GET("/templates", handler.HandleGetTemplates)
	}

	r.GET("/ws/agent", func(c *gin.Context) {
		api.HandleAgentWebSocket(c, sessionSvc)
	})

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "service": "jocky-backend"})
	})

	return r
}

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	compilerPath := flag.String("compiler", "", "Path to jocky-compile binary")
	flag.Parse()

	if *compilerPath == "" {
		if envPath := os.Getenv("JOCKY_COMPILER_PATH"); envPath != "" {
			*compilerPath = envPath
		}
	}

	warrantSvc := services.NewWarrantService()
	sessionSvc := services.NewSessionService(warrantSvc, *compilerPath)

	r := SetupRouter(sessionSvc, warrantSvc)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting JOCKY Forensic Control Backend on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server failed to run: %v", err)
	}
}
