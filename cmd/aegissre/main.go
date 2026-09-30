package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/shanurwan/AegisSRE/internal/adapters/backend"
	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	kubeadapter "github.com/shanurwan/AegisSRE/internal/adapters/kubernetes"
	reasoneradapter "github.com/shanurwan/AegisSRE/internal/adapters/reasoner"
	"github.com/shanurwan/AegisSRE/internal/adapters/telemetry"
	"github.com/shanurwan/AegisSRE/internal/app/investigator"
	"github.com/shanurwan/AegisSRE/internal/app/monitor"
	"github.com/shanurwan/AegisSRE/internal/app/operator"
	"github.com/shanurwan/AegisSRE/internal/core/model"
	"github.com/shanurwan/AegisSRE/internal/core/ports"
	"github.com/shanurwan/AegisSRE/internal/platform/audit"
	"github.com/shanurwan/AegisSRE/internal/platform/config"
	"github.com/shanurwan/AegisSRE/internal/platform/httpclient"
	runtimeadapter "github.com/shanurwan/AegisSRE/internal/platform/runtime"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
	a2atransport "github.com/shanurwan/AegisSRE/internal/transport/a2a"
	mcptransport "github.com/shanurwan/AegisSRE/internal/transport/mcp"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("aegissre stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	case "version", "--version":
		fmt.Fprintln(os.Stdout, version)
		return nil
	case "keygen":
		return keygen(args[1:])
	case "monitor", "investigator", "operator":
		if len(args) != 1 {
			return fmt.Errorf("%s does not accept positional arguments", args[0])
		}
		return runAgent(args[0])
	case "mcp-server":
		return runMCPCommand(args[1:])
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(output *os.File) {
	fmt.Fprintln(output, `AegisSRE - bounded autonomous reliability agents

Usage:
  aegissre monitor
  aegissre investigator
  aegissre operator
  aegissre mcp-server --profile=read|action
  aegissre keygen
  aegissre version

Configuration is supplied through AEGIS_* environment variables. See
.env.example and docs/deployment.md. Dry-run and mutation-off are the defaults.`)
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("keygen does not accept positional arguments")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 delegation key: %w", err)
	}
	fmt.Fprintf(os.Stdout, "AEGIS_DELEGATION_KEY_ID=%s\n", "aegissre-monitor-v1")
	fmt.Fprintf(os.Stdout, "AEGIS_DELEGATION_PRIVATE_KEY=%s\n", security.EncodePrivateKeyBase64(privateKey))
	fmt.Fprintf(os.Stdout, "AEGIS_DELEGATION_PUBLIC_KEY=%s\n", security.EncodePublicKeyBase64(publicKey))
	return nil
}

func runAgent(role string) error {
	cfg, err := config.Load(role)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	logger := configureLogger(cfg.LogLevel, role)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch role {
	case "monitor":
		return runMonitor(ctx, cfg, logger)
	case "investigator":
		return runInvestigator(ctx, cfg, logger)
	case "operator":
		return runOperator(ctx, cfg, logger)
	default:
		return fmt.Errorf("unsupported agent role %q", role)
	}
}

func runMCPCommand(args []string) error {
	flags := flag.NewFlagSet("mcp-server", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	profile := flags.String("profile", "", "tool privilege profile: read or action")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*profile != "read" && *profile != "action") {
		return errors.New("mcp-server requires --profile=read or --profile=action")
	}
	cfg, err := config.Load("mcp-" + *profile)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	logger := configureLogger(cfg.LogLevel, "mcp-"+*profile)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runMCP(ctx, cfg, *profile, logger)
}

func configureLogger(levelName, role string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(levelName) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With(
		"service", "aegissre", "role", role, "version", version,
	)
	slog.SetDefault(logger)
	return logger
}

func runMonitor(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	tools, err := connectMCP(ctx, cfg.ObserveMCPURL, "aegissre-monitor", cfg.RequestTimeout, readToolNames())
	if err != nil {
		return err
	}
	defer tools.Close()

	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}
	signer, err := monitorSigner(cfg)
	if err != nil {
		return err
	}
	policy, err := actionPolicy(cfg)
	if err != nil {
		return err
	}
	service := &monitor.Service{
		Tools: tools, Peers: a2atransport.NewClient(cfg.RequestTimeout), Signer: signer,
		Policy: policy,
		Clock:  clock, IDs: ids, Audit: audit.Logger{Log: logger}, Namespace: cfg.AllowedNamespace,
		InvestigatorURL: cfg.InvestigatorURL, OperatorURL: cfg.OperatorURL,
		Rules: monitor.DefaultRules(), VerificationCount: cfg.VerificationCount,
		Cooldown: cfg.IncidentCooldown, DelegationTTL: cfg.DelegationTTL,
		RequestTimeout: cfg.RequestTimeout, EvidenceBudget: cfg.EvidenceBudget, DryRun: cfg.DryRun,
	}
	handler, _, err := a2atransport.NewHandler(a2atransport.CardConfig{
		Name: "AegisSRE Monitor", Description: "Autonomously detects and verifies bounded reliability incidents",
		PublicURL: cfg.PublicURL, SkillID: "monitor-incidents", SkillName: "Monitor incidents",
		Examples: []string{"Autonomously poll the configured deployment health rule"},
	}, func(context.Context, model.Envelope) (model.Envelope, error) {
		return model.Envelope{}, model.NewError(model.CodeDelegationRequired, "Monitor does not accept unauthenticated remote scan triggers")
	})
	if err != nil {
		return err
	}
	go monitorLoop(ctx, service, cfg.ScanInterval, logger)
	return serve(ctx, cfg.ListenAddr, "monitor", handler, logger)
}

func monitorLoop(ctx context.Context, service *monitor.Service, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		result, err := service.Scan(ctx, monitor.ScanRequest{})
		if err != nil {
			if ctx.Err() == nil {
				logger.ErrorContext(ctx, "monitor scan failed", "error", err, "completed_outcomes", len(result.Outcomes))
			}
		} else {
			logger.InfoContext(ctx, "monitor scan complete", "candidates", result.Candidates, "outcomes", len(result.Outcomes))
		}
		for _, outcome := range result.Outcomes {
			logger.InfoContext(ctx, "incident outcome",
				"incident_id", outcome.Incident.ID, "status", outcome.Status, "detail", outcome.Detail,
			)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runInvestigator(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	tools, err := connectMCP(ctx, cfg.ObserveMCPURL, "aegissre-investigator", cfg.RequestTimeout, readToolNames())
	if err != nil {
		return err
	}
	defer tools.Close()
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}
	deterministic := ports.Reasoner(investigator.HeuristicReasoner{Clock: clock, IDs: ids})
	reasoning := deterministic
	if cfg.LLMBaseURL != "" {
		remote, err := reasoneradapter.NewResponses(
			cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel,
			httpclient.External(cfg.RequestTimeout), clock, ids,
		)
		if err != nil {
			return fmt.Errorf("configure optional Responses API reasoner: %w", err)
		}
		reasoning = reasoneradapter.Fallback{Primary: remote, Secondary: deterministic}
		logger.Info("optional Responses API reasoner enabled with deterministic fallback", "model", cfg.LLMModel)
	}
	service := &investigator.Service{
		Tools: tools, Reasoner: reasoning, Clock: clock, IDs: ids,
		Audit: audit.Logger{Log: logger}, MaxLogBytes: cfg.MaxLogBytes,
	}
	handler, _, err := a2atransport.NewHandler(a2atransport.CardConfig{
		Name: "AegisSRE Investigator", Description: "Builds evidence-driven diagnoses through constrained read-only tools",
		PublicURL: cfg.PublicURL, SkillID: "investigate-incident", SkillName: "Investigate incident",
		Examples: []string{"Diagnose a verified Deployment availability incident"},
	}, service.Handle)
	if err != nil {
		return err
	}
	return serve(ctx, cfg.ListenAddr, "investigator", handler, logger)
}

func runOperator(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	tools, err := connectMCP(ctx, cfg.OperateMCPURL, "aegissre-operator", cfg.RequestTimeout, actionToolNames())
	if err != nil {
		return err
	}
	defer tools.Close()
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}
	verifier, err := grantVerifier(cfg, model.AgentOperator)
	if err != nil {
		return err
	}
	policy, err := actionPolicy(cfg)
	if err != nil {
		return err
	}
	service := &operator.Service{
		Tools: tools, Verifier: verifier, Policy: policy, Replay: security.NewMemoryReplayGuard(),
		Clock: clock, IDs: ids, Audit: audit.Logger{Log: logger},
	}
	handler, _, err := a2atransport.NewHandler(a2atransport.CardConfig{
		Name: "AegisSRE Operator", Description: "Executes only exact, signed, policy-approved remediation delegations",
		PublicURL: cfg.PublicURL, SkillID: "operate-remediation", SkillName: "Operate remediation",
		Examples: []string{"Execute an Ed25519-signed Deployment remediation grant"},
	}, service.Handle)
	if err != nil {
		return err
	}
	return serve(ctx, cfg.ListenAddr, "operator", handler, logger)
}

func runMCP(ctx context.Context, cfg config.Config, profile string, logger *slog.Logger) error {
	var handler http.Handler
	switch profile {
	case "read":
		backend, err := observeBackend(cfg)
		if err != nil {
			return err
		}
		handler = mcptransport.HTTPHandler(mcptransport.NewReadServer(backend))
	case "action":
		backend, err := operateBackend(cfg, logger)
		if err != nil {
			return err
		}
		handler = mcptransport.HTTPHandler(mcptransport.NewActionServer(backend))
	default:
		return fmt.Errorf("unsupported MCP profile %q", profile)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.Handle("/mcp/", handler)
	return serve(ctx, cfg.ListenAddr, "mcp-"+profile, mux, logger)
}

func observeBackend(cfg config.Config) (ports.ObserveBackend, error) {
	if cfg.Backend == "fixture" {
		return fixture.Load(cfg.FixturePath)
	}
	kube, err := kubeadapter.New(cfg.Kubeconfig, cfg.AllowedNamespace)
	if err != nil {
		return nil, err
	}
	telemetryBackend := &telemetry.Victoria{
		MetricsURL: cfg.VictoriaMetricsURL, LogsURL: cfg.VictoriaLogsURL, Namespace: cfg.AllowedNamespace,
		Client: httpclient.Direct(cfg.RequestTimeout),
	}
	return backend.Observe{Telemetry: telemetryBackend, Kubernetes: kube}, nil
}

func operateBackend(cfg config.Config, logger *slog.Logger) (ports.OperateBackend, error) {
	clock, ids := runtimeadapter.Clock{}, runtimeadapter.IDs{}
	verifier, err := grantVerifier(cfg, model.AgentMCPAction)
	if err != nil {
		return nil, err
	}
	policy, err := actionPolicy(cfg)
	if err != nil {
		return nil, err
	}
	replay := security.NewMemoryReplayGuard()
	if cfg.Backend == "fixture" {
		value, err := fixture.Load(cfg.FixturePath)
		if err != nil {
			return nil, err
		}
		value.Verifier, value.Policy, value.Replay = verifier, policy, replay
		value.Clock, value.IDs, value.AllowMutations = clock, ids, cfg.AllowMutations
		return value, nil
	}
	value, err := kubeadapter.New(cfg.Kubeconfig, cfg.AllowedNamespace)
	if err != nil {
		return nil, err
	}
	value.Verifier, value.Policy, value.Replay = verifier, policy, replay
	value.Clock, value.IDs, value.Audit = clock, ids, audit.Logger{Log: logger}
	value.AllowMutations = cfg.AllowMutations
	return value, nil
}

func actionPolicy(cfg config.Config) (*security.Policy, error) {
	return security.NewPolicy(security.PolicyConfig{
		AllowedNamespaces: []string{cfg.AllowedNamespace},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment, model.ActionScaleDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: cfg.DelegationTTL, RequireDryRun: cfg.DryRun,
		MaximumReplicas: int32(cfg.MaxScaleReplicas), MaximumReplicaIncrease: int32(cfg.MaxScaleIncrease),
	})
}

func monitorSigner(cfg config.Config) (ports.GrantSigner, error) {
	if strings.TrimSpace(cfg.DelegationPrivateKey) == "" {
		return nil, nil
	}
	key, err := security.ParsePrivateKeyBase64(cfg.DelegationPrivateKey)
	if err != nil {
		return nil, err
	}
	return security.NewSigner(key, cfg.DelegationKeyID)
}

func grantVerifier(cfg config.Config, audience model.AgentID) (ports.GrantVerifier, error) {
	if strings.TrimSpace(cfg.DelegationPublicKey) == "" {
		return disabledVerifier{}, nil
	}
	key, err := security.ParsePublicKeyBase64(cfg.DelegationPublicKey)
	if err != nil {
		return nil, err
	}
	return security.NewVerifier(key, cfg.DelegationKeyID, audience)
}

type disabledVerifier struct{}

func (disabledVerifier) Verify(model.DelegationGrant, time.Time) error {
	return model.NewError(model.CodeDelegationRequired, "delegation public key is not configured")
}

func connectMCP(ctx context.Context, endpoint, name string, timeout time.Duration, expected []string) (*mcptransport.Client, error) {
	startupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var lastErr error
	for {
		attemptCtx, attemptCancel := context.WithTimeout(startupCtx, timeout)
		client, err := mcptransport.Connect(attemptCtx, endpoint, name, timeout)
		attemptCancel()
		if err == nil {
			discoveryCtx, discoveryCancel := context.WithTimeout(startupCtx, timeout)
			actual, discoverErr := client.Discover(discoveryCtx)
			discoveryCancel()
			if discoverErr == nil && slices.Equal(actual, expected) {
				return client, nil
			}
			_ = client.Close()
			if discoverErr != nil {
				lastErr = discoverErr
			} else {
				lastErr = fmt.Errorf("MCP endpoint %s exposed tools %v, expected %v", endpoint, actual, expected)
			}
		} else {
			lastErr = err
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-startupCtx.Done():
			timer.Stop()
			return nil, fmt.Errorf("connect constrained MCP service: %w", lastErr)
		case <-timer.C:
		}
	}
}

func readToolNames() []string {
	return []string{
		toolapi.ToolGetPodLogs,
		toolapi.ToolGetWorkloadSnapshot,
		toolapi.ToolSearchLogs,
		toolapi.ToolQueryMetrics,
	}
}

func actionToolNames() []string {
	return []string{toolapi.ToolExecuteRemediation, toolapi.ToolGetRemediationStatus}
}

func serve(ctx context.Context, address, role string, application http.Handler, logger *slog.Logger) error {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aegissre_build_info", Help: "AegisSRE build and process role information.",
	}, []string{"version", "role"})
	build.WithLabelValues(version, role).Set(1)
	registry.MustRegister(build)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.Handle("/", application)

	server := &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 1 << 20,
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("HTTP shutdown failed", "error", err)
		}
	}()
	logger.Info("HTTP server starting", "address", address)
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}
