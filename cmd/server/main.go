// Command server runs the threat exchange service.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threat-exchange/internal/config"
	"threat-exchange/internal/httpapi"
	"threat-exchange/internal/store"
)

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: server\n\nThreat exchange REST service. Configure through environment variables:\n"+
			"  DATABASE_URL / DATABASE_URL_FILE  Required PostgreSQL connection string\n"+
			"  HTTP_ADDR                         Listen address (%s)\n"+
			"  API_KEY / API_KEY_FILE             Optional shared key, 32+ printable ASCII bytes\n"+
			"  TLS_CERT_FILE, TLS_KEY_FILE        Optional PEM certificate and key pair\n"+
			"  RATE_LIMIT_RPS, RATE_LIMIT_BURST   Global token bucket (%d, %d)\n",
			config.DefaultHTTPAddr, config.DefaultRateRPS, config.DefaultRateBurst)
	}
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	repo, err := store.Open(startupCtx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		// connection errors can contain passwords or the configured connection string.
		return errors.New("database startup failed; verify connectivity, credentials, and schema permissions")
	}
	defer repo.Close()
	handler, err := httpapi.New(repo, httpapi.Options{
		APIKey: cfg.APIKey, RateRPS: cfg.RateRPS, RateBurst: cfg.RateBurst, Logger: logger,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		// allow body reading, processing, and response writing separate time budgets.
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" {
			serveErr <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		serveErr <- server.ListenAndServe()
	}()
	logger.Info("server starting", "addr", cfg.HTTPAddr, "tls", cfg.TLSCertFile != "", "authentication", cfg.APIKey != "")
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			if closeErr := server.Close(); closeErr != nil {
				return closeErr
			}
			return err
		}
		if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
