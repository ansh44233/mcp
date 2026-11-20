package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"strings"

	"github.com/ansh44233/mcp/internal/audit"
)

func TestAuditHealthEndpoint(t *testing.T) {
	config := Config{AuditHealth: func() audit.Health {
		return audit.Health{Persistent:true, Healthy:true, LastSequence:12}
	}}
	rec := httptest.NewRecorder()
	HandlerWithConfig(config).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit/health", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"last_sequence":12`) {
		t.Fatalf("unexpected audit health response: %s", rec.Body.String())
	}
}
