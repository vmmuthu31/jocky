package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
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
		v1.POST("/compile", handler.HandleCompileDSL)
		v1.POST("/sessions", handler.HandleCreateSession)
		v1.GET("/sessions", handler.HandleListSessions)
		v1.GET("/sessions/:id", handler.HandleGetSession)
		v1.POST("/sessions/:id/approve", handler.HandleApproveSession)
		v1.POST("/sessions/:id/evidence", handler.HandleSubmitEvidence)
		v1.POST("/sessions/:id/evidence/proto", handler.HandleSubmitEvidenceProto)
		v1.POST("/sessions/:id/domain-front", handler.HandleConfigureDomainFront)

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
	tlsCert := flag.String("tls-cert", "", "Server TLS certificate file (PEM)")
	tlsKey := flag.String("tls-key", "", "Server TLS key file (PEM)")
	tlsCA := flag.String("tls-ca", "", "CA certificate for mTLS client verification (PEM)")
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

	// mTLS mode: both cert+key required; CA cert enables client verification.
	if *tlsCert != "" && *tlsKey != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

		if *tlsCA != "" {
			caBytes, err := os.ReadFile(*tlsCA)
			if err != nil {
				log.Fatalf("Cannot read CA cert %s: %v", *tlsCA, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caBytes) {
				log.Fatalf("Failed to parse CA cert from %s", *tlsCA)
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			log.Printf("mTLS enabled — client certificates required (CA: %s)", *tlsCA)
		}

		srv := &http.Server{Addr: addr, Handler: r, TLSConfig: tlsCfg}
		log.Printf("Starting JOCKY Forensic Control Backend on %s (TLS)", addr)
		if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
			log.Fatalf("Server failed to run: %v", err)
		}
	} else {
		log.Printf("Starting JOCKY Forensic Control Backend on %s (plain HTTP — use --tls-cert/--tls-key for production)", addr)
		if err := r.Run(addr); err != nil {
			log.Fatalf("Server failed to run: %v", err)
		}
	}
}
