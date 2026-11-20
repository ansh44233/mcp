package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ansh44233/mcp/internal/security"
	platformserver "github.com/ansh44233/mcp/internal/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	os.Exit(run())
}

func run() int {
	transport := flag.String("transport", env("MCP_TRANSPORT", "stdio"), "MCP transport: stdio or http")
	addr := flag.String("http-addr", env("MCP_HTTP_ADDR", "127.0.0.1:8080"), "HTTP listen address (localhost by default)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var bearerMiddleware func(http.Handler) http.Handler
	if *transport == "http" {
		var configured bool
		var err error
		bearerMiddleware, configured, err = newHTTPBearerMiddleware(ctx, os.LookupEnv)
		if err != nil {
			logger.Error("HTTP authentication configuration rejected", "error", err)
			return 2
		}
		if configured {
			logger.Info("HTTP MCP bearer authentication enabled", "issuer", os.Getenv("MCP_OIDC_ISSUER"))
		}
	}

	runtime := platformserver.NewRuntimeWithAllStores(os.Getenv("GITHUB_TOKEN"), env("MCP_AUDIT_PATH", "./data/audit.jsonl"), env("MCP_WORKFLOW_PATH", ""), env("MCP_APPROVAL_PATH", ""))
	mcpServer := runtime.Server
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := runtime.Close(shutdownCtx); err != nil {
			logger.Error("connector shutdown incomplete", "error", err)
		}
	}()

	switch *transport {
	case "stdio":
		logger.Info("starting MCP server", "transport", "stdio", "version", platformserver.Version)
		localCtx := security.WithPrincipal(ctx, security.LocalPrincipal())
		if err := mcpServer.Run(localCtx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("MCP server stopped", "error", err)
			return 1
		}
	case "http":
		if !isLoopbackAddress(*addr) {
			logger.Error("remote HTTP is disabled until dashboard and operator API routes are authenticated; bind to localhost", "address", *addr)
			return 2
		}
		mcpHandler := mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return mcpServer },
			&mcp.StreamableHTTPOptions{Stateless: true, Logger: logger},
		)
		mux := http.NewServeMux()
		if bearerMiddleware != nil {
			mux.Handle("/mcp", bearerMiddleware(mcpHandler))
		} else {
			mux.Handle("/mcp", localPrincipalMiddleware(mcpHandler))
		}
		// The operator dashboard remains loopback-only. When OIDC is configured,
		// require the same verified bearer identity on every dashboard API route.
		dashboardHandler := runtime.DashboardHandlerWithStaticDir(env("MCP_DASHBOARD_DIR", "dashboard/dist"))
		mountDashboard(mux, dashboardHandler, bearerMiddleware)
		httpServer := &http.Server{
			Addr: *addr, Handler: mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      0,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("HTTP server graceful shutdown failed", "error", err)
			}
		}()
		logger.Info("starting Universal MCP HTTP server", "address", *addr, "mcp_path", "/mcp", "dashboard", "/")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped", "error", err)
			return 1
		}
	default:
		logger.Error("unsupported transport", "transport", *transport)
		return 2
	}
	return 0
}

func mountDashboard(mux *http.ServeMux, dashboard http.Handler, bearerMiddleware func(http.Handler) http.Handler) {
	if mux == nil || dashboard == nil {
		panic("dashboard mux and handler are required")
	}
	if bearerMiddleware != nil {
		mux.Handle("/api/", bearerMiddleware(dashboard))
	} else {
		mux.Handle("/api/", localPrincipalMiddleware(dashboard))
	}
	mux.Handle("/", dashboard)
}

func newHTTPBearerMiddleware(
	ctx context.Context,
	lookup func(string) (string, bool),
) (func(http.Handler) http.Handler, bool, error) {
	if lookup == nil {
		return nil, false, errors.New("environment lookup is required")
	}
	keys := []string{
		"MCP_OIDC_ISSUER",
		"MCP_OIDC_AUDIENCE",
		"MCP_OIDC_CLIENT_ID",
		"MCP_OIDC_CLIENT_SECRET",
		"MCP_AUTHZ_GRANTS_FILE",
	}
	values := make(map[string]string, len(keys))
	configured := 0
	for _, key := range keys {
		value, ok := lookup(key)
		if ok && value != "" {
			configured++
			values[key] = value
		}
	}
	if configured == 0 {
		return nil, false, nil
	}
	if configured != len(keys) {
		return nil, false, errors.New("MCP OIDC issuer, audience, client credentials and authorization grants file must all be configured")
	}

	grants, err := security.LoadPrincipalGrants(values["MCP_AUTHZ_GRANTS_FILE"])
	if err != nil {
		return nil, false, err
	}
	resolver, err := security.NewStaticPrincipalResolver(grants)
	if err != nil {
		return nil, false, err
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	verifier, err := security.NewOIDCIntrospectionVerifier(discoveryCtx, security.OIDCIntrospectionConfig{
		Issuer:       values["MCP_OIDC_ISSUER"],
		Audience:     values["MCP_OIDC_AUDIENCE"],
		ClientID:     values["MCP_OIDC_CLIENT_ID"],
		ClientSecret: values["MCP_OIDC_CLIENT_SECRET"],
	})
	if err != nil {
		return nil, false, err
	}
	middleware, err := security.NewBearerMiddleware(verifier, nil, resolver)
	if err != nil {
		return nil, false, err
	}
	return middleware, true, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// localPrincipalMiddleware marks loopback HTTP requests as the explicit local identity.
// This is not remote authentication; the listener is separately restricted to loopback.
func localPrincipalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := security.WithPrincipal(r.Context(), security.LocalPrincipal())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
