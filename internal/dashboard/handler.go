package dashboard

import (
	"encoding/json"
	"context"
	"net/http"
	"runtime"
	"strings"
	"time"
)

var startedAt = time.Now()

type ToolInfo struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

type ConnectorInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Operations  []string `json:"operations"`
	ReadOnly    bool     `json:"read_only"`
}

type Config struct {
	Version    string
	Transports []string
	Tools      []ToolInfo
	Connectors []ConnectorInfo
	HealthChecks map[string]func(context.Context) error
}

type status struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Status       string   `json:"status"`
	UptimeSec    int64    `json:"uptime_sec"`
	GoVersion    string   `json:"go_version"`
	Transports   []string `json:"transports"`
	Integrations []string `json:"integrations"`
	ToolCount    int      `json:"tool_count"`
}

func (c Config) currentStatus() status {
	version := c.Version
	if version == "" {
		version = "0.1.0"
	}
	transports := append([]string(nil), c.Transports...)
	integrations := make([]string, 0, len(c.Connectors))
	for _, connector := range c.Connectors {
		integrations = append(integrations, connector.ID)
	}
	return status{
		Name: "universal-mcp", Version: version, Status: "ok",
		UptimeSec: int64(time.Since(startedAt).Seconds()), GoVersion: runtime.Version(),
		Transports: transports, Integrations: integrations, ToolCount: len(c.Tools),
	}
}

// Handler serves an empty local dashboard. Production callers should use HandlerWithConfig.
func Handler() http.Handler {
	return HandlerWithConfig(Config{})
}

// HandlerWithConfig serves read-only operational metadata derived from the running platform.
func HandlerWithConfig(config Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, config.currentStatus())
	})
	mux.HandleFunc("GET /api/v1/tools", func(w http.ResponseWriter, r *http.Request) {
		query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
		result := make([]ToolInfo, 0, len(config.Tools))
		for _, tool := range config.Tools {
			if provider != "" && strings.ToLower(tool.Provider) != provider {
				continue
			}
			haystack := strings.ToLower(tool.ID + " " + tool.Name + " " + tool.Description + " " + tool.Provider + " " + tool.Risk)
			if query != "" && !strings.Contains(haystack, query) {
				continue
			}
			result = append(result, tool)
		}
		writeJSON(w, map[string]any{"tools": result, "count": len(result)})
	})
	mux.HandleFunc("GET /api/v1/connectors", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"connectors": config.Connectors, "count": len(config.Connectors)})
	})
	mux.HandleFunc("POST /api/v1/connectors/{id}/health-check", func(w http.ResponseWriter, r *http.Request) {
		check, ok := config.HealthChecks[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := check(ctx); err != nil {
			writeJSON(w, map[string]any{"connector_id": r.PathValue("id"), "status": "unhealthy", "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"connector_id": r.PathValue("id"), "status": "healthy"})
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(indexHTML))
	})
	return mux
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

const indexHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#090d18"><title>Universal MCP · Control Center</title>
<style>
:root{color-scheme:dark;--bg:#090d18;--panel:#111827;--line:#253149;--muted:#91a0b8;--text:#eef3ff;--accent:#9baaff;--green:#39d99a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 80% -10%,#26356b55,transparent),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,sans-serif}
.shell{display:grid;grid-template-columns:230px 1fr;min-height:100vh}.side{border-right:1px solid var(--line);padding:25px 17px;background:#0c1220aa}.brand{font-weight:850;font-size:19px;letter-spacing:-.5px}.brand span{color:var(--accent)}.tag{font-size:10px;color:var(--muted);margin:4px 0 30px;letter-spacing:1px}.nav{display:grid;gap:6px}.nav a{color:#b7c2d8;text-decoration:none;padding:10px 12px;border-radius:9px}.nav a:hover,.nav a.active{background:#202b46;color:white}.nav small{color:var(--muted);margin:20px 12px 5px;text-transform:uppercase;letter-spacing:1px;font-size:10px}
main{padding:32px clamp(18px,4vw,55px);max-width:1500px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}.eyebrow{color:var(--accent);font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase}h1{font-size:clamp(27px,4vw,38px);letter-spacing:-1.3px;margin:5px 0}.sub,.muted{color:var(--muted)}.pill,.chip{border:1px solid #2d4160;background:#17243b;color:#c4d0ff;padding:6px 10px;border-radius:99px;font-size:11px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:26px 0}.card,.panel{background:linear-gradient(145deg,#151f33,#101726);border:1px solid var(--line);border-radius:14px;padding:18px}.card{min-height:108px}.label{color:var(--muted);font-size:12px}.value{font-size:24px;font-weight:750;margin-top:8px;letter-spacing:-.5px}.ok{color:var(--green)}.layout{display:grid;grid-template-columns:1fr 1fr;gap:13px}.panel h2{font-size:15px;margin:0 0 13px}.panel.wide{grid-column:1/-1}.row{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;padding:12px 0;border-top:1px solid var(--line)}.row:first-of-type{border-top:0}.tool-name{font-weight:650}.tool-desc{color:var(--muted);font-size:12px;margin-top:3px}.toolbar{display:flex;gap:9px;flex-wrap:wrap;margin:10px 0 14px}input,select,button{background:#0c1424;color:var(--text);border:1px solid #35415a;border-radius:9px;padding:10px 12px;font:inherit}button{cursor:pointer}button:hover{border-color:var(--accent)}button:disabled{opacity:.5;cursor:wait}input{flex:1;min-width:180px}select{min-width:130px}.empty{border:1px dashed #35415a;border-radius:10px;padding:18px;text-align:center;color:var(--muted)}footer{margin-top:22px;color:#71809a;font-size:11px}
@media(max-width:850px){.shell{grid-template-columns:1fr}.side{border-right:0;border-bottom:1px solid var(--line);padding:14px 18px}.tag{margin:2px 0 10px}.nav{display:flex;overflow:auto}.nav small{display:none}.nav a{white-space:nowrap}.layout{grid-template-columns:1fr}.panel.wide{grid-column:auto}.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:480px){.grid{grid-template-columns:1fr}.top{align-items:flex-start}}
</style></head><body><div class="shell"><aside class="side"><div class="brand">UNIVERSAL<span> MCP</span></div><div class="tag">OPERATOR CONSOLE</div><nav class="nav"><a class="active" href="#overview">Overview</a><a href="#connectors">Connectors</a><a href="#tools">Tool catalog</a><a href="#workflows">Workflows</a></nav></aside>
<main id="overview"><div class="top"><div><div class="eyebrow">Platform operations</div><h1>Control Center</h1><div class="sub">Runtime health, connector inventory and registered MCP capabilities.</div></div><div class="pill" id="system-state">● CHECKING SYSTEM</div></div>
<div class="grid"><div class="card"><div class="label">Runtime</div><div class="value ok" id="health">—</div></div><div class="card"><div class="label">Version</div><div class="value" id="version">—</div></div><div class="card"><div class="label">Uptime</div><div class="value" id="uptime">—</div></div><div class="card"><div class="label">Registered tools</div><div class="value" id="tool-count">—</div></div></div>
<div class="layout"><section class="panel" id="connectors"><h2>Connector inventory</h2><div id="connector-list" class="muted">Loading connector metadata…</div></section>
<section class="panel" id="workflows"><h2>Workflow engine</h2><div class="empty">Not implemented yet. Workflow execution and approvals are not advertised as available.</div></section>
<section class="panel wide" id="tools"><h2>Tool catalog</h2><div class="sub">Search the exact tool definitions registered with the MCP runtime.</div><div class="toolbar"><input id="tool-search" type="search" placeholder="Search by tool, provider, description or risk…" aria-label="Search tools"><select id="provider-filter" aria-label="Filter by provider"><option value="">All providers</option></select></div><div id="tool-list" class="muted">Loading tools…</div></section></div>
<footer>Universal MCP · Operator console · <span id="refresh">Loading…</span></footer></main></div>
<script>
const $=id=>document.getElementById(id);let tools=[];
function renderTools(){const q=$('tool-search').value.toLowerCase().trim(),p=$('provider-filter').value;const rows=tools.filter(t=>(!p||t.provider===p)&&(!q||[t.id,t.name,t.description,t.provider,t.risk].join(' ').toLowerCase().includes(q)));const root=$('tool-list');root.replaceChildren();if(!rows.length){root.textContent='No tools match this filter.';root.className='empty';return}root.className='';for(const t of rows){const row=document.createElement('div');row.className='row';const left=document.createElement('div');const name=document.createElement('div');name.className='tool-name';name.textContent=t.id;const desc=document.createElement('div');desc.className='tool-desc';desc.textContent=t.description;left.append(name,desc);const meta=document.createElement('span');meta.className='chip';meta.textContent=t.provider+' · '+t.risk;row.append(left,meta);root.append(row)}}
async function load(){try{const [s,t,c]=await Promise.all(['/api/v1/status','/api/v1/tools','/api/v1/connectors'].map(u=>fetch(u,{cache:'no-store'}).then(r=>{if(!r.ok)throw Error(u+' failed');return r.json()})));$('health').textContent=s.status==='ok'?'Healthy':'Degraded';$('version').textContent=s.version;$('uptime').textContent=Math.floor(s.uptime_sec)+'s';$('tool-count').textContent=s.tool_count;$('system-state').textContent=s.status==='ok'?'● SYSTEM OPERATIONAL':'● SYSTEM DEGRADED';$('system-state').style.borderColor=s.status==='ok'?'#236d55':'#8a5731';tools=t.tools||[];const select=$('provider-filter'),selected=select.value,providers=[...new Set(tools.map(x=>x.provider))].sort();select.replaceChildren();const all=document.createElement('option');all.value='';all.textContent='All providers';select.append(all);for(const provider of providers){const option=document.createElement('option');option.value=provider;option.textContent=provider;select.append(option)}select.value=providers.includes(selected)?selected:'';renderTools();const root=$('connector-list');root.replaceChildren();if(!c.connectors.length){root.textContent='No connectors registered.';root.className='empty'}else for(const x of c.connectors){const block=document.createElement('div');block.className='row';const info=document.createElement('div');const name=document.createElement('div');name.className='tool-name';name.textContent=x.name+' · '+x.version;const desc=document.createElement('div');desc.className='tool-desc';desc.textContent=x.description;const ops=document.createElement('div');ops.className='tool-desc';ops.textContent=x.operations.length+' operations · '+(x.read_only?'read-only':'mixed access');info.append(name,desc,ops);const actions=document.createElement('div');const tag=document.createElement('span');tag.className='chip';tag.textContent='Registered';const check=document.createElement('button');check.type='button';check.textContent='Check health';const result=document.createElement('div');result.className='tool-desc';check.addEventListener('click',async()=>{check.disabled=true;result.textContent='Checking…';try{const response=await fetch('/api/v1/connectors/'+encodeURIComponent(x.id)+'/health-check',{method:'POST'});const data=await response.json();result.textContent=data.status==='healthy'?'Health check passed':('Health check failed: '+(data.error||'unknown error'))}catch(e){result.textContent='Health check request failed'}finally{check.disabled=false}});actions.append(tag,check,result);block.append(info,actions);root.append(block)}$('refresh').textContent='Updated '+new Date().toLocaleTimeString()}catch(e){$('health').textContent='Unavailable';$('system-state').textContent='● API UNAVAILABLE';$('refresh').textContent='Could not load platform metadata'}}
$('tool-search').addEventListener('input',renderTools);$('provider-filter').addEventListener('change',renderTools);load();setInterval(load,10000);
</script></body></html>`
