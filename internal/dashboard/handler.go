package dashboard

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

var startedAt = time.Now()

type status struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Status       string   `json:"status"`
	UptimeSec    int64    `json:"uptime_sec"`
	GoVersion    string   `json:"go_version"`
	Transports   []string `json:"transports"`
	Integrations []string `json:"integrations"`
}

func currentStatus() status {
	return status{
		Name:         "universal-mcp",
		Version:      "0.1.0",
		Status:       "ok",
		UptimeSec:    int64(time.Since(startedAt).Seconds()),
		GoVersion:    runtime.Version(),
		Transports:   []string{"stdio", "streamable-http"},
		Integrations: []string{},
	}
}

// Handler serves the local operator dashboard and its read-only status endpoint.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(currentStatus())
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(indexHTML))
	})
	return mux
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#090d18">
<title>Universal MCP · Control Center</title>
<style>
:root{color-scheme:dark;--bg:#090d18;--panel:#111827;--line:#253149;--muted:#91a0b8;--text:#eef3ff;--accent:#8b9cff;--green:#39d99a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 80% -10%,#26356b55,transparent),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,sans-serif}
.shell{display:grid;grid-template-columns:245px 1fr;min-height:100vh}.side{border-right:1px solid var(--line);padding:26px 18px;background:#0c1220aa}.brand{font-weight:800;font-size:19px;letter-spacing:-.5px}.brand span{color:var(--accent)}.tag{font-size:11px;color:var(--muted);margin:4px 0 34px}.nav{display:grid;gap:7px}.nav a{color:#b7c2d8;text-decoration:none;padding:10px 12px;border-radius:9px}.nav a.active,.nav a:hover{background:#202b46;color:white}.nav small{display:block;color:var(--muted);margin:24px 12px 7px;text-transform:uppercase;letter-spacing:1px;font-size:10px}
main{padding:34px clamp(20px,4vw,58px);max-width:1500px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap}.eyebrow{color:var(--accent);font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase}h1{font-size:clamp(28px,4vw,40px);letter-spacing:-1.4px;margin:5px 0}.sub{color:var(--muted)}.pill{border:1px solid #236d55;background:#103326;color:#73e9b8;padding:7px 11px;border-radius:99px;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:28px 0}.card{background:linear-gradient(145deg,#151f33,#101726);border:1px solid var(--line);border-radius:15px;padding:19px;min-height:116px}.label{color:var(--muted);font-size:12px}.value{font-size:25px;font-weight:750;margin-top:9px;letter-spacing:-.6px}.ok{color:var(--green)}.section{display:grid;grid-template-columns:1.35fr 1fr;gap:14px}.panel{background:#111827;border:1px solid var(--line);border-radius:15px;padding:20px}.panel h2{font-size:16px;margin:0 0 14px}.row{display:flex;justify-content:space-between;gap:15px;padding:12px 0;border-top:1px solid var(--line)}.row:first-of-type{border-top:0}.muted{color:var(--muted)}.empty{border:1px dashed #35415a;border-radius:12px;padding:20px;text-align:center;color:var(--muted)}footer{margin-top:24px;color:#71809a;font-size:12px}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.section{grid-template-columns:1fr}.shell{grid-template-columns:1fr}.side{border-right:0;border-bottom:1px solid var(--line);padding:16px 20px}.tag{margin:2px 0 12px}.nav{display:flex;overflow:auto}.nav small{display:none}.nav a{white-space:nowrap}}
@media(max-width:480px){.grid{grid-template-columns:1fr}.top{align-items:flex-start}}
</style></head>
<body><div class="shell"><aside class="side"><div class="brand">UNIVERSAL<span> MCP</span></div><div class="tag">CONTROL CENTER · PREVIEW</div><nav class="nav"><a class="active" href="/">Overview</a><small>Platform</small><a href="#connectors">Connectors</a><a href="#tools">Tools</a><a href="#workflows">Workflows</a><small>Operations</small><a href="#activity">Activity</a><a href="#security">Security</a></nav></aside>
<main><div class="top"><div><div class="eyebrow">Platform overview</div><h1>Control Center</h1><div class="sub">A live operational snapshot of your MCP runtime.</div></div><div class="pill">● SYSTEM OPERATIONAL</div></div>
<div class="grid"><div class="card"><div class="label">Runtime status</div><div class="value ok" id="health">Healthy</div></div><div class="card"><div class="label">Server version</div><div class="value" id="version">0.1.0</div></div><div class="card"><div class="label">Uptime</div><div class="value" id="uptime">—</div></div><div class="card"><div class="label">Connectors</div><div class="value" id="connectors">0</div></div></div>
<div class="section"><section class="panel"><h2>Platform services</h2><div class="row"><span>MCP runtime</span><b class="ok">Operational</b></div><div class="row"><span>Operator dashboard</span><b class="ok">Operational</b></div><div class="row"><span>Health API</span><b class="ok">Operational</b></div><div class="row"><span>Provider integrations</span><span class="muted">Not configured</span></div></section>
<section class="panel" id="connectors"><h2>Connected providers</h2><div class="empty">No providers connected yet.<br>GitHub is planned as the first connector.</div></section>
<section class="panel" id="tools"><h2>Tool registry</h2><div class="row"><span>platform_status</span><span class="ok">Available</span></div><div class="muted">More tools will appear as connectors are implemented.</div></section>
<section class="panel" id="workflows"><h2>Workflow engine</h2><div class="empty">Workflow execution is planned. No workflows are currently running.</div></section></div>
<footer>Universal MCP · Foundation preview · <span id="refresh">Refreshing status…</span></footer></main></div>
<script>
async function refresh(){try{const r=await fetch('/api/v1/status',{cache:'no-store'});if(!r.ok)throw Error('status unavailable');const s=await r.json();document.getElementById('health').textContent=s.status==='ok'?'Healthy':'Degraded';document.getElementById('version').textContent=s.version;document.getElementById('uptime').textContent=Math.floor(s.uptime_sec)+'s';document.getElementById('connectors').textContent=s.integrations.length;document.getElementById('refresh').textContent='Updated '+new Date().toLocaleTimeString()}catch(e){document.getElementById('health').textContent='Unavailable';document.getElementById('health').className='value';document.getElementById('refresh').textContent='Status API unavailable'}}
refresh();setInterval(refresh,5000);
</script></body></html>`
