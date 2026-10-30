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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/shanurwan/AegisSRE/internal/adapters/backend"
	"github.com/shanurwan/AegisSRE/internal/adapters/fixture"
	kubeadapter "github.com/shanurwan/AegisSRE/internal/adapters/kubernetes"
	notificationadapter "github.com/shanurwan/AegisSRE/internal/adapters/notification"
	postgresadapter "github.com/shanurwan/AegisSRE/internal/adapters/postgres"
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
	"github.com/shanurwan/AegisSRE/internal/platform/observability"
	runtimeadapter "github.com/shanurwan/AegisSRE/internal/platform/runtime"
	"github.com/shanurwan/AegisSRE/internal/platform/tlsconfig"
	"github.com/shanurwan/AegisSRE/internal/security"
	"github.com/shanurwan/AegisSRE/internal/toolapi"
	a2atransport "github.com/shanurwan/AegisSRE/internal/transport/a2a"
	"github.com/shanurwan/AegisSRE/internal/transport/authn"
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
	case "migrate":
		if len(args) != 1 {
			return errors.New("migrate does not accept positional arguments")
		}
		return runMigrations()
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
  aegissre migrate
  aegissre keygen
  aegissre version

Configuration is supplied through AEGIS_* environment variables. See
.env.example and docs/deployment.md. Dry-run and mutation-off are the defaults.`)
}

func runMigrations() error {
	cfg, err := config.Load("migrate")
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := openPostgres(ctx, cfg, false)
	if err != nil {
		return err
	}
	if pool == nil {
		return errors.New("AEGIS_DATABASE_URL or AEGIS_DATABASE_URL_FILE is required for migrate")
	}
	defer pool.Close()
	if err := postgresadapter.Migrate(ctx, pool); err != nil {
		return err
	}
	return postgresadapter.CheckSchema(ctx, pool)
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
	shutdownTelemetry, err := observability.Setup(ctx, role, version)
	if err != nil {
		return fmt.Errorf("initialize OpenTelemetry: %w", err)
	}
	defer shutdownObservability(shutdownTelemetry, logger)

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
	shutdownTelemetry, err := observability.Setup(ctx, "mcp-"+*profile, version)
	if err != nil {
		return fmt.Errorf("initialize OpenTelemetry: %w", err)
	}
	defer shutdownObservability(shutdownTelemetry, logger)
	return runMCP(ctx, cfg, *profile, logger)
}

func shutdownObservability(shutdown observability.Shutdown, logger *slog.Logger) {
	if shutdown == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		logger.Error("OpenTelemetry shutdown failed", "error", err)
	}
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
	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	logger := slog.New(observability.NewContextHandler(base)).With(
		"service", "aegissre", "role", role, "version", version,
	)
	slog.SetDefault(logger)
	return logger
}

func runMonitor(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	pool, err := openPostgres(ctx, cfg, true)
	if err != nil {
		return err
	}
	if pool != nil {
		defer pool.Close()
	}
	tools, err := connectMCP(ctx, cfg, cfg.ObserveMCPURL, "aegissre-monitor", model.AgentMCPObserve, readToolNames())
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
	rules, err := configuredMonitorRules(cfg)
	if err != nil {
		return err
	}
	peers, err := peerMessenger(cfg)
	if err != nil {
		return err
	}
	auditor := ports.Auditor(audit.Logger{Log: logger})
	var monitorState ports.MonitorStateStore
	if pool != nil {
		monitorState, err = postgresadapter.NewMonitorState(pool)
		if err != nil {
			return fmt.Errorf("configure durable Monitor coordination state: %w", err)
		}
		auditor, err = postgresadapter.NewAuditor(pool)
		if err != nil {
			return fmt.Errorf("configure durable Monitor audit log: %w", err)
		}
	}
	service := &monitor.Service{
		Tools: tools, Peers: peers,
		Signer: signer, ReportSigner: signer,
		Policy: policy,
		Clock:  clock, IDs: ids, Audit: auditor, Namespace: cfg.AllowedNamespace,
		InvestigatorURL: cfg.InvestigatorURL, OperatorURL: cfg.OperatorURL,
		Rules: rules, VerificationCount: cfg.VerificationCount,
		Cooldown: cfg.IncidentCooldown, DelegationTTL: cfg.DelegationTTL,
		RequestTimeout: cfg.RequestTimeout, EvidenceBudget: cfg.EvidenceBudget, DryRun: cfg.DryRun,
		AllowLogTraceActions: cfg.AllowLogTraceActions,
		StateStore:           monitorState, InstanceID: runtimeInstanceID(cfg), StateLease: cfg.StateLease,
	}
	handler, _, err := a2atransport.NewHandler(a2atransport.CardConfig{
		Name: "AegisSRE Monitor", Description: "Autonomously detects and verifies bounded reliability incidents",
		PublicURL: cfg.PublicURL, SkillID: "monitor-incidents", SkillName: "Monitor incidents",
		Examples:    []string{"Autonomously poll the configured deployment health rule"},
		RequireMTLS: cfg.MTLSEnabled,
	}, func(context.Context, model.Envelope) (model.Envelope, error) {
		return model.Envelope{}, model.NewError(model.CodeDelegationRequired, "Monitor does not accept unauthenticated remote scan triggers")
	})
	if err != nil {
		return err
	}
	go monitorLoop(ctx, service, cfg.ScanInterval, logger)
	return serve(ctx, cfg, "monitor", model.AgentMonitor, handler, logger, postgresReadiness(pool))
}

func monitorLoop(ctx context.Context, service *monitor.Service, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		scanCtx, finishSpan := observability.StartOperation(ctx, "aegissre.monitor.scan")
		result, err := service.Scan(scanCtx, monitor.ScanRequest{})
		finishSpan(err)
		if err != nil {
			if ctx.Err() == nil {
				logger.ErrorContext(scanCtx, "monitor scan failed", "error", err, "completed_outcomes", len(result.Outcomes))
			}
		} else {
			logger.InfoContext(scanCtx, "monitor scan complete", "candidates", result.Candidates, "outcomes", len(result.Outcomes))
		}
		for _, outcome := range result.Outcomes {
			logMonitorOutcome(scanCtx, logger, outcome)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func logMonitorOutcome(ctx context.Context, logger *slog.Logger, outcome monitor.IncidentOutcome) {
	incidentFields := []any{
		"incident_id", outcome.Incident.ID,
		"status", outcome.Status,
		"detail", outcome.Detail,
	}
	if outcome.Status == string(model.IncidentResolved) && outcome.Grant != nil {
		incidentFields = append(incidentFields,
			"grant_id", outcome.Grant.GrantID,
			"target_api_version", outcome.Grant.Action.Target.APIVersion,
			"target_kind", outcome.Grant.Action.Target.Kind,
			"target_namespace", outcome.Grant.Action.Target.Namespace,
			"target_name", outcome.Grant.Action.Target.Name,
		)
	}
	logger.InfoContext(ctx, "incident outcome", incidentFields...)

	if outcome.Report == nil {
		return
	}
	report := outcome.Report.Report
	reportFields := []any{
		"incident_id", report.IncidentID,
		"report_id", report.ReportID,
		"target_api_version", report.Target.APIVersion,
		"target_kind", report.Target.Kind,
		"target_namespace", report.Target.Namespace,
		"target_name", report.Target.Name,
		"notification_channel", outcome.Report.Notification.Channel,
		"notification_status", outcome.Report.Notification.Status,
	}
	if report.Execution != nil {
		reportFields = append(reportFields, "grant_id", report.Execution.GrantID)
	}
	logger.InfoContext(ctx, "incident report outcome", reportFields...)
}

func runInvestigator(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	tools, err := connectMCP(ctx, cfg, cfg.ObserveMCPURL, "aegissre-investigator", model.AgentMCPObserve, readToolNames())
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
		Examples:    []string{"Diagnose a verified Deployment availability incident"},
		RequireMTLS: cfg.MTLSEnabled,
	}, service.Handle)
	if err != nil {
		return err
	}
	return serve(ctx, cfg, "investigator", model.AgentInvestigator, handler, logger, nil)
}

func runOperator(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	pool, err := openPostgres(ctx, cfg, true)
	if err != nil {
		return err
	}
	if pool != nil {
		defer pool.Close()
	}

	tools, err := connectMCP(ctx, cfg, cfg.OperateMCPURL, "aegissre-operator", model.AgentMCPAction, actionToolNames())
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
	auditor := ports.Auditor(audit.Logger{Log: logger})
	var executionStore ports.ActionExecutionStore
	var reportOutbox ports.ReportOutboxStore
	if pool != nil {
		executionStore, err = postgresadapter.NewExecutionLedger(pool, 0)
		if err != nil {
			return fmt.Errorf("configure durable Operator execution ledger: %w", err)
		}
		auditor, err = postgresadapter.NewAuditor(pool)
		if err != nil {
			return fmt.Errorf("configure durable Operator audit log: %w", err)
		}
		reportOutbox, err = postgresadapter.NewReportOutbox(pool)
		if err != nil {
			return fmt.Errorf("configure durable incident report store: %w", err)
		}
	}
	var notifier ports.Notifier
	if cfg.WhatsAppEnabled {
		notifier, err = notificationadapter.NewWhatsApp(notificationadapter.Config{
			GraphVersion: cfg.WhatsAppGraphVersion, PhoneNumberID: cfg.WhatsAppPhoneID,
			AccessToken: cfg.WhatsAppAccessToken, Recipient: cfg.WhatsAppRecipient,
			Template: cfg.WhatsAppTemplate, Language: cfg.WhatsAppLanguage,
			// The durable outbox owns bounded retries. Retrying independently in
			// the provider adapter would make delivery attempts unobservable.
			MaxRetries: 0, Client: httpclient.External(cfg.RequestTimeout),
		})
		if err != nil {
			return fmt.Errorf("configure WhatsApp notifier: %w", err)
		}
		logger.Info("WhatsApp incident report delivery enabled", "template", cfg.WhatsAppTemplate, "graph_version", cfg.WhatsAppGraphVersion)
	}
	service := &operator.Service{
		Tools: tools, Verifier: verifier, ReportVerifier: verifier,
		Policy: policy, Clock: clock, IDs: ids, Audit: auditor, Notifier: notifier,
		ExecutionStore: executionStore, ReportOutbox: reportOutbox,
		InstanceID: runtimeInstanceID(cfg), ExecutionLease: cfg.StateLease, RequestTimeout: cfg.RequestTimeout,
	}
	if executionStore == nil {
		service.Replay = security.NewMemoryReplayGuard()
	}
	handler, _, err := a2atransport.NewHandler(a2atransport.CardConfig{
		Name: "AegisSRE Operator", Description: "Executes only exact, signed, policy-approved remediation delegations",
		PublicURL: cfg.PublicURL, SkillID: "operate-remediation", SkillName: "Operate remediation",
		Examples:    []string{"Execute an Ed25519-signed Deployment remediation grant"},
		RequireMTLS: cfg.MTLSEnabled,
	}, service.Handle)
	if err != nil {
		return err
	}

	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	if reportOutbox != nil && cfg.WhatsAppEnabled {
		worker := &operator.OutboxWorker{
			Store: reportOutbox, Notifier: notifier, Audit: auditor, Clock: clock,
			InstanceID: runtimeInstanceID(cfg), Lease: cfg.StateLease,
			MaxAttempts: cfg.OutboxMaxAttempts, PollInterval: cfg.OutboxPollInterval,
			DeliveryTimeout: cfg.RequestTimeout,
		}
		go func() {
			if workerErr := worker.Run(runCtx); workerErr != nil {
				stop(fmt.Errorf("notification outbox worker stopped: %w", workerErr))
			}
		}()
	}
	serveErr := serve(runCtx, cfg, "operator", model.AgentOperator, handler, logger, postgresReadiness(pool))
	if serveErr != nil {
		return serveErr
	}
	if cause := context.Cause(runCtx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

func runMCP(ctx context.Context, cfg config.Config, profile string, logger *slog.Logger) error {
	var handler http.Handler
	var pool *pgxpool.Pool
	switch profile {
	case "read":
		backend, err := observeBackend(cfg)
		if err != nil {
			return err
		}
		handler = mcptransport.HTTPHandler(mcptransport.NewReadServer(backend))
	case "action":
		var err error
		pool, err = openPostgres(ctx, cfg, true)
		if err != nil {
			return err
		}
		if pool != nil {
			defer pool.Close()
		}
		var executionStore ports.ActionExecutionStore
		auditor := ports.Auditor(audit.Logger{Log: logger})
		if pool != nil {
			executionStore, err = postgresadapter.NewExecutionLedger(pool, 0)
			if err != nil {
				return fmt.Errorf("configure durable action MCP execution ledger: %w", err)
			}
			auditor, err = postgresadapter.NewAuditor(pool)
			if err != nil {
				return fmt.Errorf("configure durable action MCP audit log: %w", err)
			}
		}
		backend, err := operateBackend(cfg, logger, executionStore, auditor)
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
	recipient := model.AgentMCPObserve
	if profile == "action" {
		recipient = model.AgentMCPAction
	}
	return serve(ctx, cfg, "mcp-"+profile, recipient, mux, logger, postgresReadiness(pool))
}

func observeBackend(cfg config.Config) (ports.ObserveBackend, error) {
	var (
		observe  ports.ObserveBackend
		resolver backend.PodOwnerResolver
	)
	if cfg.Backend == "fixture" {
		value, err := fixture.Load(cfg.FixturePath)
		if err != nil {
			return nil, err
		}
		observe, resolver = value, value
	} else {
		kube, err := kubeadapter.New(cfg.Kubeconfig, cfg.AllowedNamespace)
		if err != nil {
			return nil, err
		}
		telemetryBackend := &telemetry.Victoria{
			MetricsURL: cfg.VictoriaMetricsURL, LogsURL: cfg.VictoriaLogsURL,
			TracesURL: cfg.VictoriaTracesURL, Namespace: cfg.AllowedNamespace,
			Client: observability.HTTPClient(httpclient.Direct(cfg.RequestTimeout)),
		}
		observe, resolver = backend.Observe{Telemetry: telemetryBackend, Kubernetes: kube}, kube
	}
	if cfg.WorkloadPolicyPath == "" {
		return observe, nil
	}
	document, err := security.LoadWorkloadPolicy(cfg.WorkloadPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load exact read MCP workload policy: %w", err)
	}
	return backend.NewPolicyObserve(observe, document.Workloads, resolver)
}

func operateBackend(
	cfg config.Config,
	logger *slog.Logger,
	executionStore ports.ActionExecutionStore,
	auditor ports.Auditor,
) (ports.OperateBackend, error) {
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
	value.Verifier, value.Policy = verifier, policy
	value.Clock, value.IDs, value.Audit = clock, ids, auditor
	value.AllowMutations = cfg.AllowMutations
	value.ExecutionStore = executionStore
	value.InstanceID = runtimeInstanceID(cfg)
	value.ExecutionLease = cfg.StateLease
	value.RequestTimeout = cfg.RequestTimeout
	if executionStore == nil {
		value.Replay = replay
	}
	return value, nil
}

func actionPolicy(cfg config.Config) (*security.Policy, error) {
	policyConfig := security.PolicyConfig{
		AllowedNamespaces: []string{cfg.AllowedNamespace},
		AllowedActions:    []model.ActionKind{model.ActionRestartDeployment, model.ActionScaleDeployment},
		MinimumConfidence: 0.8, MinimumEvidence: 1,
		MaximumGrantTTL: cfg.DelegationTTL, RequireDryRun: cfg.DryRun,
		MaximumReplicas: int32(cfg.MaxScaleReplicas), MaximumReplicaIncrease: int32(cfg.MaxScaleIncrease), // #nosec G115 -- Config.Validate bounds both to [1,1000]
	}
	if cfg.WorkloadPolicyPath != "" {
		document, err := security.LoadWorkloadPolicy(cfg.WorkloadPolicyPath)
		if err != nil {
			return nil, fmt.Errorf("load exact workload policy: %w", err)
		}
		for _, workload := range document.Workloads {
			if workload.Target.Namespace != cfg.AllowedNamespace {
				return nil, model.NewError(model.CodeOutOfScope, "workload policy target is outside AEGIS_ALLOWED_NAMESPACE")
			}
		}
		policyConfig.PolicyID = document.PolicyID
		policyConfig.Workloads = document.Workloads
		policyConfig.RequirePolicyBinding = true
	}
	return security.NewPolicy(policyConfig)
}

func configuredMonitorRules(cfg config.Config) ([]monitor.Rule, error) {
	rules := monitor.DefaultRules()
	if cfg.WorkloadPolicyPath == "" {
		return rules, nil
	}
	document, err := security.LoadWorkloadPolicy(cfg.WorkloadPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load Monitor workload policy rules: %w", err)
	}
	enabled := make(map[model.EvidenceSource]struct{}, 3)
	for _, workload := range document.Workloads {
		for _, source := range workload.AllowedSignalSources {
			enabled[source] = struct{}{}
		}
	}
	filtered := make([]monitor.Rule, 0, len(rules))
	for _, rule := range rules {
		if _, ok := enabled[rule.Source]; ok {
			filtered = append(filtered, rule)
		}
	}
	if len(filtered) == 0 {
		return nil, model.NewError(model.CodeInvalidInput, "workload policy enables none of Monitor's bounded detection rules")
	}
	return filtered, nil
}

type monitorAuthorizationSigner interface {
	ports.GrantSigner
	ports.ReportRequestSigner
}

func monitorSigner(cfg config.Config) (monitorAuthorizationSigner, error) {
	if strings.TrimSpace(cfg.DelegationPrivateKey) == "" && cfg.DelegationPrivateKeyFile == "" {
		return nil, nil
	}
	var (
		key ed25519.PrivateKey
		err error
	)
	if cfg.DelegationPrivateKeyFile != "" {
		key, err = security.LoadPrivateKeyFile(cfg.DelegationPrivateKeyFile)
	} else {
		key, err = security.ParsePrivateKeyBase64(cfg.DelegationPrivateKey)
	}
	if err != nil {
		return nil, err
	}
	return security.NewSigner(key, cfg.DelegationKeyID)
}

type authorizationVerifier interface {
	ports.GrantVerifier
	ports.ReportRequestVerifier
}

func grantVerifier(cfg config.Config, audience model.AgentID) (authorizationVerifier, error) {
	if cfg.DelegationPublicKeysFile != "" {
		keys, err := security.LoadPublicKeyringFile(cfg.DelegationPublicKeysFile)
		if err != nil {
			return nil, err
		}
		return security.NewKeyringVerifier(keys, audience)
	}
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

func (disabledVerifier) VerifyReportRequest(model.IncidentReportRequest, time.Time) error {
	return model.NewError(model.CodeDelegationRequired, "delegation public key is not configured")
}

func connectMCP(ctx context.Context, cfg config.Config, endpoint, name string, recipient model.AgentID, expected []string) (*mcptransport.Client, error) {
	httpClient, err := authenticatedHTTPClient(cfg, recipient)
	if err != nil {
		return nil, err
	}
	startupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var lastErr error
	for {
		attemptCtx, attemptCancel := context.WithTimeout(startupCtx, cfg.RequestTimeout)
		client, err := mcptransport.ConnectWithHTTPClient(attemptCtx, endpoint, name, cfg.RequestTimeout, httpClient)
		attemptCancel()
		if err == nil {
			discoveryCtx, discoveryCancel := context.WithTimeout(startupCtx, cfg.RequestTimeout)
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

func peerMessenger(cfg config.Config) (ports.PeerMessenger, error) {
	if !cfg.MTLSEnabled {
		return a2atransport.NewClient(cfg.RequestTimeout), nil
	}
	clients := make(map[model.AgentID]*http.Client, 2)
	for _, peer := range []model.AgentID{model.AgentInvestigator, model.AgentOperator} {
		client, err := authenticatedHTTPClient(cfg, peer)
		if err != nil {
			return nil, err
		}
		clients[peer] = client
	}
	return a2atransport.NewAuthenticatedClient(clients), nil
}

func authenticatedHTTPClient(cfg config.Config, recipient model.AgentID) (*http.Client, error) {
	if !cfg.MTLSEnabled {
		return nil, nil
	}
	identities := workloadIdentities(cfg)
	expectedIdentity, ok := identities[recipient]
	if !ok {
		return nil, model.NewError(model.CodeOutOfScope, "mTLS destination role is not configured")
	}
	tlsConfig, err := tlsconfig.LoadClient(tlsconfig.Files{
		Certificate: cfg.TLSCertificateFile, PrivateKey: cfg.TLSPrivateKeyFile,
		CA: cfg.TLSCAFile, Identity: cfg.TLSIdentity,
	}, expectedIdentity)
	if err != nil {
		return nil, fmt.Errorf("load authenticated client transport for %s: %w", recipient, err)
	}
	return observability.HTTPClient(httpclient.DirectTLS(cfg.RequestTimeout, tlsConfig)), nil
}

func workloadIdentities(cfg config.Config) map[model.AgentID]string {
	prefix := "spiffe://" + cfg.TrustDomain + "/ns/" + cfg.SystemNamespace + "/sa/"
	return map[model.AgentID]string{
		model.AgentMonitor:      prefix + "aegis-monitor",
		model.AgentInvestigator: prefix + "aegis-investigator",
		model.AgentOperator:     prefix + "aegis-operator",
		model.AgentMCPObserve:   prefix + "aegis-mcp-read",
		model.AgentMCPAction:    prefix + "aegis-mcp-action",
	}
}

func openPostgres(ctx context.Context, cfg config.Config, checkSchema bool) (*pgxpool.Pool, error) {
	databaseURL, err := configuredDatabaseURL(cfg)
	if err != nil {
		return nil, err
	}
	if databaseURL == "" {
		return nil, nil
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("AEGIS_DATABASE_URL is not a valid PostgreSQL connection string")
	}
	if err := validatePostgresTransport(cfg, poolConfig); err != nil {
		return nil, err
	}
	poolConfig.MaxConns = int32(cfg.DatabaseMaxConnections) // #nosec G115 -- Config.Validate bounds this to [1,50]
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	poolConfig.ConnConfig.ConnectTimeout = cfg.RequestTimeout
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "aegissre-" + cfg.Role
	poolConfig.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", cfg.RequestTimeout.Milliseconds())
	poolConfig.ConnConfig.RuntimeParams["lock_timeout"] = "5000"
	poolConfig.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "30000"
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open durable PostgreSQL state: %w", err)
	}
	readyCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	if err := pool.Ping(readyCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect durable PostgreSQL state: %w", err)
	}
	if checkSchema {
		if err := postgresadapter.CheckSchema(readyCtx, pool); err != nil {
			pool.Close()
			return nil, err
		}
	}
	return pool, nil
}

func validatePostgresTransport(cfg config.Config, poolConfig *pgxpool.Config) error {
	requireVerifiedTLS := cfg.Role == "migrate" || cfg.MTLSEnabled &&
		(cfg.Role == "monitor" || cfg.Role == "operator" || cfg.Role == "mcp-action")
	if !requireVerifiedTLS {
		return nil
	}
	if poolConfig == nil || poolConfig.ConnConfig == nil ||
		poolConfig.ConnConfig.TLSConfig == nil ||
		poolConfig.ConnConfig.TLSConfig.InsecureSkipVerify ||
		poolConfig.ConnConfig.TLSConfig.ServerName == "" {
		return errors.New("authenticated production PostgreSQL requires sslmode=verify-full with a trusted server CA")
	}
	for _, fallback := range poolConfig.ConnConfig.Fallbacks {
		if fallback == nil || fallback.TLSConfig == nil ||
			fallback.TLSConfig.InsecureSkipVerify || fallback.TLSConfig.ServerName == "" {
			return errors.New("authenticated production PostgreSQL fallbacks must verify TLS hostnames")
		}
	}
	return nil
}

func configuredDatabaseURL(cfg config.Config) (string, error) {
	if cfg.DatabaseURL != "" {
		return cfg.DatabaseURL, nil
	}
	if cfg.DatabaseURLFile == "" {
		return "", nil
	}
	info, err := os.Stat(cfg.DatabaseURLFile)
	if err != nil {
		return "", fmt.Errorf("read PostgreSQL URL file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return "", errors.New("PostgreSQL URL file is empty, oversized, or not regular")
	}
	data, err := os.ReadFile(cfg.DatabaseURLFile)
	if err != nil {
		return "", fmt.Errorf("read PostgreSQL URL file: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("PostgreSQL URL file is empty")
	}
	return value, nil
}

func runtimeInstanceID(cfg config.Config) string {
	if cfg.InstanceID != "" {
		return cfg.InstanceID
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	value := cfg.Role + "-" + strings.TrimSpace(hostname)
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

type readinessCheck func(context.Context) error

func postgresReadiness(pool *pgxpool.Pool) readinessCheck {
	if pool == nil {
		return nil
	}
	return func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("postgres ping: %w", err)
		}
		return postgresadapter.CheckSchema(ctx, pool)
	}
}

func readToolNames() []string {
	return []string{
		toolapi.ToolGetPodLogs,
		toolapi.ToolGetWorkloadSnapshot,
		toolapi.ToolQueryLogSignals,
		toolapi.ToolSearchLogs,
		toolapi.ToolQueryMetrics,
		toolapi.ToolQueryTraceSignals,
	}
}

func actionToolNames() []string {
	return []string{
		toolapi.ToolExecuteRemediation,
		toolapi.ToolGetRemediationResult,
		toolapi.ToolGetRemediationStatus,
	}
}

func serve(
	ctx context.Context,
	cfg config.Config,
	role string,
	recipient model.AgentID,
	application http.Handler,
	logger *slog.Logger,
	ready readinessCheck,
) error {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aegissre_build_info", Help: "AegisSRE build and process role information.",
	}, []string{"version", "role"})
	build.WithLabelValues(version, role).Set(1)
	registry.MustRegister(build)

	operations := http.NewServeMux()
	operations.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	operations.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if ready != nil {
			readyCtx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
			defer cancel()
			if err := ready(readyCtx); err != nil {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte("not ready\n"))
				return
			}
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	operations.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	if !cfg.MTLSEnabled {
		mux := http.NewServeMux()
		mux.Handle("/healthz", operations)
		mux.Handle("/readyz", operations)
		mux.Handle("/metrics", operations)
		mux.Handle("/", application)
		server := newHTTPServer(cfg.ListenAddr, observability.HTTPHandler(role, mux))
		logger.Info("HTTP server starting", "address", cfg.ListenAddr, "mutual_tls", false)
		return runHTTPServers(ctx, logger, serverSpec{server: server})
	}

	authorizer, err := authn.NewRoleAuthorizer(recipient, workloadIdentities(cfg))
	if err != nil {
		return fmt.Errorf("configure mTLS role authorization: %w", err)
	}
	tlsConfig, err := tlsconfig.LoadServer(tlsconfig.Files{
		Certificate: cfg.TLSCertificateFile, PrivateKey: cfg.TLSPrivateKeyFile,
		CA: cfg.TLSCAFile, Identity: cfg.TLSIdentity,
	})
	if err != nil {
		return fmt.Errorf("configure mTLS listener: %w", err)
	}
	protected := http.NewServeMux()
	protected.Handle("/", authorizer.Middleware(application))
	applicationServer := newHTTPServer(cfg.ListenAddr, observability.HTTPHandler(role, protected))
	applicationServer.TLSConfig = tlsConfig
	adminServer := newHTTPServer(cfg.AdminListenAddr, operations)
	logger.Info("mTLS application and health-only admin servers starting",
		"application_address", cfg.ListenAddr, "admin_address", cfg.AdminListenAddr,
		"identity", cfg.TLSIdentity,
	)
	return runHTTPServers(ctx, logger,
		serverSpec{server: applicationServer, tls: true},
		serverSpec{server: adminServer},
	)
}

// securityHeaders stops browsers from content-sniffing JSON into active
// content and from embedding responses in cross-origin pages. CORS reads of
// the public Agent Card are governed separately by CORS, not by CORP.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(writer, request)
	})
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: address, Handler: securityHeaders(handler), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 1 << 20,
	}
}

type serverSpec struct {
	server *http.Server
	tls    bool
}

func runHTTPServers(ctx context.Context, logger *slog.Logger, specifications ...serverSpec) error {
	if len(specifications) == 0 {
		return errors.New("at least one HTTP server is required")
	}
	results := make(chan error, len(specifications))
	for _, specification := range specifications {
		specification := specification
		go func() {
			var err error
			if specification.tls {
				err = specification.server.ListenAndServeTLS("", "")
			} else {
				err = specification.server.ListenAndServe()
			}
			results <- err
		}()
	}

	var firstErr error
	select {
	case <-ctx.Done():
	case firstErr = <-results:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, specification := range specifications {
		if err := specification.server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP shutdown failed", "address", specification.server.Addr, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr == nil || errors.Is(firstErr, http.ErrServerClosed) {
		return nil
	}
	return firstErr
}
