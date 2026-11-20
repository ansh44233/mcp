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

	"github.com/ansh44233/mcp/internal/dashboard"
	platformserver "github.com/ansh44233/mcp/internal/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	transport := flag.String("transport", env("MCP_TRANSPORT", "stdio"), "MCP transport: stdio or http")
	addr := flag.String("http-addr", env("MCP_HTTP_ADDR", "127.0.0.1:8080"), "HTTP listen address (localhost by default)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mcpServer := platformserver.New()
	switch *transport {
	case "stdio":
		logger.Info("starting MCP server", "transport", "stdio", "version", platformserver.Version)
		if err := mcpServer.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("MCP server stopped", "error", err)
			os.Exit(1)
		}
	case "http":
		if !isLoopbackAddress(*addr) {
			logger.Error("remote HTTP is disabled until authentication and authorization are implemented; bind to localhost", "address", *addr)
			os.Exit(2)
		}
		mcpHandler := mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return mcpServer },
			&mcp.StreamableHTTPOptions{Stateless: true, Logger: logger},
		)
		mux := http.NewServeMux()
		mux.Handle("/mcp", mcpHandler)
		mux.Handle("/", dashboard.Handler())
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
			_ = httpServer.Shutdown(shutdownCtx)
		}()
		logger.Info("starting Universal MCP HTTP server", "address", *addr, "mcp_path", "/mcp", "dashboard", "/")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped", "error", err)
			os.Exit(1)
		}
	default:
		logger.Error("unsupported transport", "transport", *transport)
		os.Exit(2)
	}
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
