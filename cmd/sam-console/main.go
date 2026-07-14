package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/sam/internal/console"
)

func main() {
	var (
		hubURL     = flag.String("hub", "http://localhost:8080", "URL of the SAM control plane")
		adminToken = flag.String("admin-token", "", "Admin token for control plane authentication")
		bindAddr   = flag.String("bind-addr", ":8081", "Address to bind the console server")
		staticDir  = flag.String("static-dir", "public", "Directory containing static frontend files")
	)
	flag.Parse()

	if *adminToken == "" {
		log.Fatal("Admin token is required (via --admin-token)")
	}

	srv, err := console.NewServer(console.Config{
		HubURL:     *hubURL,
		AdminToken: *adminToken,
		StaticDir:  *staticDir,
	})
	if err != nil {
		log.Fatalf("Failed to initialize console server: %v", err)
	}

	httpSrv := &http.Server{
		Addr:    *bindAddr,
		Handler: srv.Handler(),
	}

	go func() {
		log.Printf("SAM Console listening on %s", *bindAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Console server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Shutting down console server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
}
