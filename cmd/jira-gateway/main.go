// Command jira-gateway is a reference Jira gateway: it accepts a CI OIDC
// token, checks a per-repository grant on every call and forwards allowed
// calls to Atlassian with a client_credentials token only it holds.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nonflux/tmp-jira-gateway/internal/audit"
	"github.com/nonflux/tmp-jira-gateway/internal/auth"
	"github.com/nonflux/tmp-jira-gateway/internal/config"
	"github.com/nonflux/tmp-jira-gateway/internal/preflight"
	"github.com/nonflux/tmp-jira-gateway/internal/server"
	"github.com/nonflux/tmp-jira-gateway/internal/upstream"
)

func main() {
	configPath := flag.String("config", "/etc/jira-gateway/config/config.json", "path to the config file (settings and grants)")
	check := flag.Bool("check", false, "validate the config file and exit; reads no secret and makes no network call")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		fmt.Printf("config ok: %d grant(s), audience %s, issuer %s\n", len(cfg.Grants), cfg.Audience, cfg.Issuer)
		return
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	log := audit.New(os.Stdout)
	hc := upstream.NewHTTPClient(30 * time.Second)

	var read, write *upstream.TokenSource
	if cfg.ReadClientIDFile != "" {
		read = upstream.NewTokenSource("read", cfg.ReadClientIDFile, cfg.ReadClientSecretFile, cfg.TokenURL, hc, log)
		if err := read.CheckFiles(); err != nil {
			return err
		}
	}
	if cfg.WriteClientIDFile != "" {
		write = upstream.NewTokenSource("write", cfg.WriteClientIDFile, cfg.WriteClientSecretFile, cfg.TokenURL, hc, log)
		if err := write.CheckFiles(); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	verifier, err := auth.New(dctx, cfg.Issuer, cfg.Audience, time.Duration(cfg.ClockSkewSeconds)*time.Second, &http.Client{Timeout: 15 * time.Second})
	cancel()
	if err != nil {
		return err
	}

	addr := cfg.Listen
	if addr == "" {
		addr = ":8080"
		if p := os.Getenv("PORT"); p != "" {
			addr = ":" + p
		}
	}
	fwd := upstream.NewForwarder(cfg.UpstreamBaseURL, hc, read, write, cfg.MaxResponseBytes)
	srv := &http.Server{
		Addr: addr,
		Handler: &server.Handler{
			Config:    cfg,
			Verifier:  verifier,
			Forwarder: fwd,
			Preflight: preflight.New(fwd, time.Duration(*cfg.PreflightCacheSeconds)*time.Second),
			Log:       log,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Event("INFO", "started", fmt.Sprintf("listening on %s, %d grant(s)", addr, len(cfg.Grants)))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	err = srv.Shutdown(sctx)
	log.Event("INFO", "stopped", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
