import { useEffect, useMemo, useState } from "react";

type Status = {
  name: string;
  version: string;
  status: string;
  uptime_sec: number;
  go_version: string;
  transports: string[];
  integrations: string[];
  tool_count: number;
};
type Tool = { id: string; provider: string; name: string; description: string; risk: string };
type Connector = {
  id: string; name: string; version: string; description: string;
  operations: string[]; read_only: boolean;
};
type AuditEvent = {
  sequence: number; timestamp: string; actor_id: string; provider: string;
  tool_id: string; risk: string; outcome: string; duration: number;
};
type AuditHealth = { persistent: boolean; healthy: boolean; last_sequence: number };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [tools, setTools] = useState<Tool[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [auditHealth, setAuditHealth] = useState<AuditHealth | null>(null);
  const [query, setQuery] = useState("");
  const [provider, setProvider] = useState("all");
  const [updated, setUpdated] = useState<Date | null>(null);
  const [error, setError] = useState("");

  async function refresh() {
    try {
      const [s, t, c, a, h] = await Promise.all([
        api<Status>("/api/v1/status"),
        api<{ tools: Tool[] }>("/api/v1/tools"),
        api<{ connectors: Connector[] }>("/api/v1/connectors"),
        api<{ events: AuditEvent[] }>("/api/v1/audit?limit=25"),
        api<AuditHealth>("/api/v1/audit/health"),
      ]);
      setStatus(s); setTools(t.tools); setConnectors(c.connectors);
      setEvents(a.events); setAuditHealth(h); setUpdated(new Date()); setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Dashboard API unavailable");
    }
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => window.clearInterval(timer);
  }, []);

  const providers = useMemo(() => [...new Set(tools.map((tool) => tool.provider))].sort(), [tools]);
  const filteredTools = useMemo(() => tools.filter((tool) => {
    const matchesProvider = provider === "all" || tool.provider === provider;
    const haystack = [tool.id, tool.name, tool.description, tool.provider, tool.risk].join(" ").toLowerCase();
    return matchesProvider && haystack.includes(query.toLowerCase().trim());
  }), [tools, provider, query]);

  async function checkConnector(id: string) {
    return api<{ status: string; error?: string }>(`/api/v1/connectors/${encodeURIComponent(id)}/health-check`, { method: "POST" });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview">UNIVERSAL<span> MCP</span></a>
        <p className="sidebar-caption">OPERATOR CONSOLE</p>
        <nav>
          <a className="selected" href="#overview">Overview</a>
          <a href="#connectors">Connectors</a>
          <a href="#tools">Tool catalog</a>
          <a href="#audit">Audit log</a>
          <a href="#workflows">Workflows</a>
        </nav>
        <div className="sidebar-foot">LOCAL CONTROL PLANE<br />READ-ONLY CONSOLE</div>
      </aside>

      <main id="overview">
        <header className="page-header">
          <div><div className="eyebrow">PLATFORM OPERATIONS</div><h1>Control Center</h1>
            <p>Runtime health, connector inventory and registered MCP capabilities.</p></div>
          <div className={`system-pill ${status?.status === "ok" ? "healthy" : "unavailable"}`}>
            <span />{status?.status === "ok" ? "SYSTEM OPERATIONAL" : "SYSTEM UNAVAILABLE"}
          </div>
        </header>

        {error && <div className="error-banner" role="alert">{error}</div>}

        <section className="metric-grid" aria-label="Platform metrics">
          <Metric label="Runtime" value={status?.status === "ok" ? "Healthy" : "—"} />
          <Metric label="Version" value={status?.version ?? "—"} />
          <Metric label="Uptime" value={status ? formatUptime(status.uptime_sec) : "—"} />
          <Metric label="Registered tools" value={status ? String(status.tool_count) : "—"} />
        </section>

        <div className="content-grid">
          <section className="panel" id="connectors">
            <SectionTitle eyebrow="INTEGRATIONS" title="Connector inventory" />
            {connectors.length === 0 ? <Empty>No connectors registered.</Empty> : connectors.map((connector) =>
              <ConnectorRow key={connector.id} connector={connector} onCheck={checkConnector} />)}
          </section>

          <section className="panel" id="audit">
            <SectionTitle eyebrow="GOVERNANCE" title="Audit log" />
            <div className="audit-state">
              <span className={auditHealth?.healthy ? "dot good" : "dot"} />
              {auditHealth ? `${auditHealth.persistent ? "Persistent" : "In-memory"} · ${auditHealth.healthy ? "Integrity OK" : "Integrity issue"} · ${auditHealth.last_sequence} events` : "Checking audit integrity…"}
            </div>
            {events.length === 0 ? <Empty>No audit events recorded yet.</Empty> : events.map((event) =>
              <div className="audit-row" key={event.sequence}>
                <div><strong>{event.tool_id}</strong><small>{event.actor_id || "local"} · {event.provider} · {new Date(event.timestamp).toLocaleString()}</small></div>
                <span className={`outcome outcome-${event.outcome}`}>{event.outcome}</span>
              </div>)}
          </section>

          <section className="panel panel-wide" id="tools">
            <SectionTitle eyebrow="MCP CAPABILITIES" title="Tool catalog" />
            <p className="panel-description">Search the tool definitions registered with the MCP runtime.</p>
            <div className="toolbar">
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search tools, providers, descriptions…" aria-label="Search tools" />
              <select value={provider} onChange={(e) => setProvider(e.target.value)} aria-label="Filter by provider">
                <option value="all">All providers</option>
                {providers.map((item) => <option key={item} value={item}>{item}</option>)}
              </select>
            </div>
            <div className="table-head"><span>TOOL</span><span>PROVIDER / RISK</span></div>
            {filteredTools.length === 0 ? <Empty>No tools match this filter.</Empty> : filteredTools.map((tool) =>
              <div className="tool-row" key={tool.id}>
                <div><strong>{tool.id}</strong><small>{tool.description}</small></div>
                <span className="tag">{tool.provider} · {tool.risk}</span>
              </div>)}
            <div className="result-count">Showing {filteredTools.length} of {tools.length} tools</div>
          </section>

          <section className="panel panel-wide" id="workflows">
            <SectionTitle eyebrow="AUTOMATION" title="Workflow engine" />
            <Empty>Workflow execution and durable checkpoints are not implemented yet.</Empty>
          </section>
        </div>
        <footer>Universal MCP · Operator console <span>{updated ? `Updated ${updated.toLocaleTimeString()}` : "Connecting…"}</span></footer>
      </main>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <article className="metric"><span>{label}</span><strong>{value}</strong></article>;
}
function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return <div className="section-title"><span>{eyebrow}</span><h2>{title}</h2></div>;
}
function Empty({ children }: { children: React.ReactNode }) {
  return <div className="empty-state">{children}</div>;
}
function ConnectorRow({ connector, onCheck }: { connector: Connector; onCheck: (id: string) => Promise<{status: string; error?: string}> }) {
  const [result, setResult] = useState("");
  const [busy, setBusy] = useState(false);
  async function runCheck() {
    setBusy(true); setResult("Checking…");
    try { const response = await onCheck(connector.id); setResult(response.status === "healthy" ? "Health check passed" : `Health check failed: ${response.error ?? "unknown error"}`); }
    catch { setResult("Health check request failed"); }
    finally { setBusy(false); }
  }
  return <div className="connector-row">
    <div><strong>{connector.name} <span className="version">{connector.version}</span></strong>
      <small>{connector.description}</small>
      <small>{connector.operations.length} operations · {connector.read_only ? "read-only" : "mixed access"}</small>
      {result && <small className="check-result" role="status">{result}</small>}
    </div>
    <button onClick={() => void runCheck()} disabled={busy}>{busy ? "Checking…" : "Check health"}</button>
  </div>;
}
function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m`;
}
