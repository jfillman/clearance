package slack

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FileSecret reads a mounted secret file on each call; on a read error it returns "" (the call then fails as
// unauthenticated, loudly, rather than using a stale value).
func FileSecret(path string) func() string {
	return func() string {
		b, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
}

// Build wires the service from a configuration and a store (OpenPG in a deployment, MemStore in a test).
func Build(cfg Config, st Store, log *slog.Logger) (*Service, error) {
	routes, err := LoadRoutes(cfg.RoutesFile)
	if err != nil {
		return nil, err
	}
	api := NewAPI(cfg.SlackAPIBase, cfg.BotToken, cfg.MinPostInterval)
	if cfg.BotTokenFile != "" {
		api.BotTokenFn = FileSecret(cfg.BotTokenFile)
	}
	client := &Client{API: cfg.APIURL, Core: cfg.CoreURL, TokenFile: cfg.SATokenFile, OnBehalfHeader: cfg.OnBehalfOfHeader,
		HTTP:      &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		UserAgent: "clearance-slack", ForwardAuthTime: cfg.ForwardAuthTime}
	// The stream is long-lived: its own client with no overall timeout (the server ends it after ten minutes).
	streamHTTP := &http.Client{CheckRedirect: client.HTTP.CheckRedirect}
	notifier := &Notifier{Cfg: &cfg, Routes: routes, Store: st, Slack: api, Clear: client, Log: log}
	streamClient := *client
	streamClient.HTTP = streamHTTP
	notifier.StreamClear = &streamClient
	link := NewLinkFlow(&cfg, st, log)
	svc := &Service{Cfg: &cfg, Store: st, Slack: api, Clear: client, Link: link, Notifier: notifier, Log: log,
		Dedupe: NewDedupe(cfg.ReplayWindow+time.Minute, 10000)}
	link.OnLinked = func(ctx context.Context, l Link) {
		ch, err := api.OpenDM(ctx, l.User)
		if err != nil {
			return
		}
		_ = api.Ephemeral(ctx, ch, l.User, "Linked to "+l.Person+". Clearance will message you about changes waiting on you, and you can clear (up to tier "+itoa(cfg.ClearMaxTier)+") and deny from the buttons.")
	}
	return svc, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

// Mux is the HTTP surface: health, the link pages and, for the Events transport, the Slack endpoints.
func (s *Service) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	s.Link.Mount(mux)
	if s.Cfg.Transport == TransportEvents {
		(&EventsHTTP{Secret: s.Cfg.SigningSecret, Window: s.Cfg.ReplayWindow, Handler: s, Log: s.Log,
			Dedupe: NewDedupe(s.Cfg.ReplayWindow+time.Minute, 10000)}).Mount(mux)
	}
	return mux
}

// Run serves until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	if err := s.Store.Migrate(ctx); err != nil {
		return errors.New("migrating the store failed: " + err.Error())
	}
	srv := &http.Server{Addr: s.Cfg.Listen, Handler: s.Mux(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	errc := make(chan error, 1)
	run(func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	})
	if s.Cfg.Transport == TransportSocket {
		sock := &Socket{API: s.Slack, AppToken: s.Cfg.AppToken, Handler: s, Log: s.Log, Dedupe: NewDedupe(10*time.Minute, 10000)}
		if s.Cfg.AppTokenFile != "" {
			sock.AppTokenFn = FileSecret(s.Cfg.AppTokenFile)
		}
		run(func() { _ = sock.Run(ctx) })
	}
	run(func() { s.Notifier.Run(ctx) })
	run(func() { s.Notifier.RunAlerts(ctx) })
	run(func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.SweepDeactivated(ctx)
			}
		}
	})
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	wg.Wait()
	return err
}
