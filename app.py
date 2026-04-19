import os
import json
import itertools
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv

load_dotenv()

# ─── Rodízio de API Keys ──────────────────────────────────────────────────────

abuse_keys  = [v for k, v in sorted(os.environ.items()) if k.startswith("ABUSEIPDB_KEY_") and v]
flow_keys   = [v for k, v in sorted(os.environ.items()) if k.startswith("FLOW_KEY_") and v]
abuse_cycle = itertools.cycle(abuse_keys) if abuse_keys else None
flow_cycle  = itertools.cycle(flow_keys)  if flow_keys  else None

# ─── Helpers ─────────────────────────────────────────────────────────────────

def json_request(method, url, headers=None, data=None):
    body = json.dumps(data).encode() if data else None
    req  = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        try:    return json.loads(e.read() or b"{}"), e.code
        except: return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 500

# ─── HTML ─────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Match IP</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

:root {
  --bg:      #050d1a;
  --bg2:     #071428;
  --bg3:     #0a1e3d;
  --border:  #0d3060;
  --border2: #1a5aaa;
  --green:   #00e5a0;
  --green2:  #00b87c;
  --blue:    #00aaff;
  --blue2:   #0066cc;
  --red:     #ff4466;
  --yellow:  #ffcc00;
  --text:    #cde4ff;
  --text2:   #6a9fd8;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  background-image:
    radial-gradient(ellipse at 15% 0%,   #00aaff12 0%, transparent 55%),
    radial-gradient(ellipse at 85% 100%, #00e5a012 0%, transparent 55%);
}

::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 10px; }

/* ── HEADER ── */
header {
  display: flex; align-items: center; justify-content: center; gap: 16px;
  padding: 32px 24px 24px;
  border-bottom: 1px solid var(--border);
  position: relative;
}
header::after {
  content: '';
  position: absolute; bottom: -1px; left: 50%; transform: translateX(-50%);
  width: 200px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--blue), var(--green), transparent);
}
.logo {
  width: 52px; height: 52px;
  background: linear-gradient(135deg, var(--blue2), var(--green2));
  border-radius: 14px;
  display: flex; align-items: center; justify-content: center;
  font-size: 26px;
  box-shadow: 0 0 24px #00aaff30, 0 4px 12px #00000040;
}
.header-text h1 {
  font-size: 1.9rem; font-weight: 700; letter-spacing: .5px;
  background: linear-gradient(90deg, var(--blue), var(--green));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.header-text p { font-size: .8rem; color: var(--text2); margin-top: 3px; letter-spacing: .3px; }

/* ── CONTAINER ── */
.wrap { max-width: 820px; margin: 0 auto; padding: 32px 20px 80px; }

/* ── CARD ── */
.card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 28px;
  margin-bottom: 18px;
  position: relative;
  overflow: hidden;
  box-shadow: 0 4px 30px #00000030;
}
.card::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent 5%, var(--blue) 40%, var(--green) 60%, transparent 95%);
  opacity: .7;
}

/* ── INPUTS ── */
label {
  display: block; font-size: .72rem; font-weight: 600;
  color: var(--text2); text-transform: uppercase; letter-spacing: .8px;
  margin-bottom: 8px;
}
input[type=text] {
  width: 100%; padding: 12px 16px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 10px; color: var(--text);
  font-size: .95rem; font-family: 'JetBrains Mono', monospace;
  transition: border-color .2s, box-shadow .2s;
  margin-bottom: 0;
}
input[type=text]:focus {
  outline: none; border-color: var(--blue);
  box-shadow: 0 0 0 3px #00aaff15;
}

/* ── BUTTON ── */
.btn {
  padding: 12px 26px; border: none; border-radius: 10px;
  font-size: .92rem; font-weight: 600; cursor: pointer;
  transition: all .2s; white-space: nowrap;
}
.btn-blue {
  background: linear-gradient(135deg, #0077dd, #004ea8);
  color: #fff; border: 1px solid #0088ff66;
  box-shadow: 0 0 16px #0077dd30;
}
.btn-blue:hover  { filter: brightness(1.25); transform: translateY(-2px); box-shadow: 0 4px 20px #0077dd40; }
.btn:disabled    { opacity: .4; cursor: not-allowed; transform: none !important; filter: none !important; }

/* ── ROW ── */
.row { display: flex; gap: 10px; align-items: stretch; flex-wrap: wrap; }
.row input { flex: 1; min-width: 180px; }

/* ── SPINNER ── */
.spin {
  display: inline-block; width: 14px; height: 14px;
  border: 2px solid #ffffff30; border-top-color: #fff;
  border-radius: 50%; animation: rot .7s linear infinite;
  vertical-align: middle; margin-left: 8px;
}
@keyframes rot { to { transform: rotate(360deg); } }

/* ── RESULT BOX ── */
.rbox {
  margin-top: 20px; padding: 20px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 14px; font-size: .88rem; line-height: 1.7;
}
.rbox.ok  { border-color: #00e5a030; box-shadow: 0 0 20px #00e5a010; }
.rbox.bad { border-color: #ff446630; box-shadow: 0 0 20px #ff446610; }

/* ── SCORE BAR ── */
.sbar-wrap { margin: 14px 0 4px; }
.sbar-labels { display: flex; justify-content: space-between; font-size: .75rem; color: var(--text2); margin-bottom: 6px; }
.sbar-bg   { height: 7px; border-radius: 99px; background: var(--bg); overflow: hidden; }
.sbar-fill { height: 100%; border-radius: 99px; transition: width .7s cubic-bezier(.4,0,.2,1); }

/* ── BADGES ── */
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 3px 11px; border-radius: 99px;
  font-size: .73rem; font-weight: 700; margin: 2px 3px;
}
.b-green  { background: #00e5a018; color: var(--green);  border: 1px solid #00e5a035; }
.b-blue   { background: #00aaff18; color: var(--blue);   border: 1px solid #00aaff35; }
.b-red    { background: #ff446618; color: var(--red);    border: 1px solid #ff446635; }
.b-yellow { background: #ffcc0018; color: var(--yellow); border: 1px solid #ffcc0035; }
.b-gray   { background: #ffffff0c; color: var(--text2);  border: 1px solid #ffffff18; }

/* ── INFO GRID ── */
.ig { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 10px; margin-top: 16px; }
.ig-item {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px;
  transition: border-color .2s;
}
.ig-item:hover { border-color: var(--border2); }
.ig-item .lbl { font-size: .68rem; color: var(--text2); text-transform: uppercase; letter-spacing: .6px; }
.ig-item .val { font-size: .9rem; font-weight: 600; margin-top: 5px; font-family: 'JetBrains Mono', monospace; }

/* ── AI BOX ── */
.ai-box {
  margin-top: 18px; padding: 18px 20px;
  background: #030c1c;
  border: 1px solid #1a4a8a;
  border-left: 3px solid var(--green);
  border-radius: 12px;
}
.ai-label {
  font-size: .7rem; text-transform: uppercase; letter-spacing: 1px;
  color: var(--green); font-weight: 700;
  display: flex; align-items: center; gap: 7px; margin-bottom: 10px;
}
.ai-label::before { content:''; display:inline-block; width:6px; height:6px; border-radius:50%; background:var(--green); animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.ai-box p { font-size: .87rem; line-height: 1.8; color: var(--text); }

/* ── REPORTS LOG ── */
.log {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px;
  font-size: .8rem; font-family: 'JetBrains Mono', monospace;
  max-height: 130px; overflow-y: auto; margin-top: 6px;
}
.log-row { padding: 4px 0; border-bottom: 1px solid var(--border); color: var(--text2); }
.log-row:last-child { border-bottom: none; }
.log-row span { color: var(--blue); }

/* ── LINK ── */
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── MARKDOWN ── */
.md { font-size: .88rem; line-height: 1.8; color: var(--text); }
.md h1,.md h2,.md h3 { color: var(--blue); margin: 14px 0 6px; font-size: 1rem; }
.md strong { color: var(--text); font-weight: 700; }
.md em { color: var(--text2); }
.md ul,.md ol { padding-left: 20px; margin: 8px 0; }
.md li { margin: 4px 0; }
.md hr { border: none; border-top: 1px solid var(--border); margin: 12px 0; }
.md p { margin: 6px 0; }
.md code { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; font-family: 'JetBrains Mono', monospace; font-size: .82rem; color: var(--green); }
.placeholder {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 12px;
  padding: 40px 20px; color: var(--text2); text-align: center;
}
.placeholder .icon { font-size: 2.8rem; opacity: .5; }
.placeholder p { font-size: .88rem; max-width: 340px; line-height: 1.6; }
</style>
</head>
<body>

<header>
  <div class="logo">🛡️</div>
  <div class="header-text">
    <h1>Match IP</h1>
    <p>Scanner &amp; Analisador de Ameaças em Tempo Real</p>
  </div>
</header>

<div class="wrap">
  <div class="card">
    <label>Endereço IP</label>
    <div class="row">
      <input type="text" id="ip-input" placeholder="Ex: 8.8.8.8 ou 185.220.101.1"
             onkeydown="if(event.key==='Enter')scanIP()"/>
      <button class="btn btn-blue" id="btn-scan" onclick="scanIP()">🔍 Analisar</button>
    </div>
  </div>

  <div id="result-area">
    <div class="card">
      <div class="placeholder">
        <div class="icon">🌐</div>
        <p>Digite um endereço IP acima e clique em <strong>Analisar</strong> para ver o relatório completo com análise de IA.</p>
      </div>
    </div>
  </div>
</div>

<div style="text-align:center;padding:10px 0 24px;opacity:.3;transition:opacity .3s" onmouseover="this.style.opacity='.7'" onmouseout="this.style.opacity='.3'">
  <span style="font-size:.65rem;font-family:'JetBrains Mono',monospace;background:linear-gradient(90deg,#0a3a6a,#0a5a4a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:.5px">
    Criado por <a href="https://github.com/FlowTemperature" target="_blank" style="background:linear-gradient(90deg,#1a6aaa,#0a9a7a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-decoration:none;font-weight:700">FlowTemperature</a>
    &nbsp;·&nbsp;
    com ajuda de <span style="background:linear-gradient(90deg,#0a5a9a,#0a4a7a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700">Claude</span>
  </span>
</div>

<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script>
async function scanIP() {
  const ip  = document.getElementById('ip-input').value.trim();
  if (!ip)  return alert('Digite um endereço IP!');

  const btn = document.getElementById('btn-scan');
  const out = document.getElementById('result-area');
  btn.disabled = true;
  btn.innerHTML = 'Analisando <span class="spin"></span>';
  out.innerHTML = `<div class="card"><div class="placeholder"><div class="icon">⏳</div><p>Buscando informações sobre <strong>${ip}</strong>...</p></div></div>`;

  try {
    const r = await fetch('/api/check/' + encodeURIComponent(ip));
    const j = await r.json();

    if (j.error) {
      out.innerHTML = `<div class="card"><div class="rbox bad">❌ Erro: ${j.error.message || JSON.stringify(j.error)}</div></div>`;
      return;
    }

    const d     = j.data;
    const score = d.abuseConfidenceScore || 0;
    const barC  = score >= 75 ? 'var(--red)' : score >= 30 ? 'var(--yellow)' : 'var(--green)';
    const bc    = score >= 75 ? 'b-red'      : score >= 30 ? 'b-yellow'      : 'b-green';
    const cls   = score >= 75 ? 'bad'        : 'ok';

    out.innerHTML = `
    <div class="card">
      <div class="rbox ${cls}">
        <div style="display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:8px">
          <span style="font-size:1.15rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--blue)">${d.ipAddress}</span>
          <span class="badge ${bc}">${score}% abuso</span>
          ${d.isWhitelisted ? '<span class="badge b-green">✓ Whitelist</span>' : ''}
          ${d.isTor         ? '<span class="badge b-red">⚠ Tor</span>'        : ''}
          ${d.usageType     ? `<span class="badge b-gray">${d.usageType}</span>` : ''}
        </div>

        <div class="sbar-wrap">
          <div class="sbar-labels">
            <span>Nível de Ameaça</span>
            <span style="color:${barC};font-weight:700">${score}/100</span>
          </div>
          <div class="sbar-bg">
            <div class="sbar-fill" style="width:${score}%;background:${barC}"></div>
          </div>
        </div>

        <div class="ig">
          <div class="ig-item"><div class="lbl">País</div><div class="val">${d.countryCode||'N/A'} ${d.countryName||''}</div></div>
          <div class="ig-item"><div class="lbl">ISP</div><div class="val" style="font-size:.78rem">${d.isp||'N/A'}</div></div>
          <div class="ig-item"><div class="lbl">Reportes</div><div class="val">${d.totalReports}</div></div>
          <div class="ig-item"><div class="lbl">Último reporte</div><div class="val" style="font-size:.75rem">${d.lastReportedAt ? new Date(d.lastReportedAt).toLocaleDateString('pt-BR') : 'Nunca'}</div></div>
          <div class="ig-item"><div class="lbl">Domínio</div><div class="val" style="font-size:.78rem">${d.domain||'N/A'}</div></div>
          <div class="ig-item"><div class="lbl">Uso</div><div class="val" style="font-size:.75rem">${d.usageType||'N/A'}</div></div>
        </div>

        ${d.reports && d.reports.length ? `
        <div style="margin-top:16px;font-size:.72rem;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">📋 Últimos Reportes</div>
        <div class="log">
          ${d.reports.slice(0,5).map(r=>`
          <div class="log-row"><span>[${new Date(r.reportedAt).toLocaleString('pt-BR')}]</span> ${r.comment||'sem comentário'}</div>`).join('')}
        </div>` : ''}

        <div style="margin-top:16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <a href="https://www.abuseipdb.com/check/${d.ipAddress}" target="_blank" class="badge b-blue">🔗 Ver no AbuseIPDB</a>
        </div>
      </div>

      <div class="ai-box" id="ai-out">
        <div class="ai-label">Análise de IA <span class="spin" style="border-top-color:var(--green)"></span></div>
        <p style="color:var(--text2)">Gerando análise de segurança com Llama 3.1...</p>
      </div>
    </div>`;

    // Chama Flow API
    const ai  = await fetch('/api/flow', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message:
        `Você é um especialista sênior em cibersegurança e threat intelligence. Analise o seguinte IP com base nos dados fornecidos e entregue um relatório técnico em português brasileiro.\n\n` +
        `═══════════════════════════════\n` +
        `IP ANALISADO: ${ip}\n` +
        `Score de Abuso (AbuseIPDB): ${score}/100\n` +
        `País: ${d.countryCode} — ${d.countryName||'desconhecido'}\n` +
        `ISP / Provedor: ${d.isp||'desconhecido'}\n` +
        `Domínio associado: ${d.domain||'nenhum'}\n` +
        `Tipo de uso: ${d.usageType||'desconhecido'}\n` +
        `Total de reportes: ${d.totalReports}\n` +
        `Último reporte: ${d.lastReportedAt ? new Date(d.lastReportedAt).toLocaleString('pt-BR') : 'nunca reportado'}\n` +
        `Nó Tor: ${d.isTor ? 'SIM — alto risco de anonimização' : 'Não'}\n` +
        `Whitelist: ${d.isWhitelisted ? 'Sim' : 'Não'}\n` +
        `${d.reports && d.reports.length ? 'Últimos comentários de abuso:\\n' + d.reports.slice(0,3).map(r => '• ' + (r.comment||'sem comentário')).join('\\n') : ''}\n` +
        `═══════════════════════════════\n\n` +
        `Com base nesses dados, responda em formato estruturado:\n\n` +
        `🔴 NÍVEL DE AMEAÇA: (Crítico / Alto / Médio / Baixo / Seguro) — justifique em 1 linha\n\n` +
        `🕵️ PERFIL DO IP: Descreva o que este IP provavelmente representa (ex: servidor VPN, bot de brute-force, scanner de portas, exit node Tor, infraestrutura legítima, etc.) com base nos dados.\n\n` +
        `⚠️ RISCOS IDENTIFICADOS: Liste os principais riscos associados a este IP de forma técnica e objetiva.\n\n` +
        `🛡️ RECOMENDAÇÕES: Dê ações concretas que um administrador de sistemas ou analista de segurança deveria tomar em relação a este IP (bloquear, monitorar, investigar, ignorar, etc.) e o motivo.\n\n` +
        `Seja direto, técnico e útil. Não repita os dados brutos, interprete-os.`
      })
    });
    const aj  = await ai.json();
    document.getElementById('ai-out').innerHTML =
      `<div class="ai-label">Análise de IA</div><div class="md">${marked.parse(aj.reply || aj.error || 'Sem resposta.')}</div>`;

  } catch(e) {
    out.innerHTML = `<div class="card"><div class="rbox bad">❌ Erro inesperado: ${e.message}</div></div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔍 Analisar';
  }
}
</script>
</body>
</html>"""

HTML_BYTES = HTML.encode("utf-8")

# ─── Handler ──────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def do_OPTIONS(self):
        # CORS para a CLI conseguir acessar
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # GET /ping — health check para a CLI
        if self.path == "/ping":
            self.send_json({"status": "ok", "version": "1.0.0"}); return

        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(HTML_BYTES))
            self.end_headers()
            self.wfile.write(HTML_BYTES)
            return

        if self.path.startswith("/api/check/"):
            ip = urllib.parse.unquote(self.path[len("/api/check/"):])
            if not abuse_cycle:
                self.send_json({"error": {"message": "Sem chaves AbuseIPDB configuradas"}}, 500); return
            data, status = json_request(
                "GET",
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose=true",
                headers={"Key": next(abuse_cycle), "Accept": "application/json"}
            )
            self.send_json(data, status); return

        self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}")

        # POST /analyze  — endpoint para a CLI
        if self.path == "/analyze":
            ip = body.get("ip", "").strip()
            if not ip:
                self.send_json({"error": "IP obrigatório"}, 400); return
            if not abuse_cycle:
                self.send_json({"error": "Sem chaves AbuseIPDB"}, 500); return

            abuse_data, _ = json_request(
                "GET",
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose=true",
                headers={"Key": next(abuse_cycle), "Accept": "application/json"}
            )
            d     = abuse_data.get("data", {})
            score = d.get("abuseConfidenceScore", 0)

            ai_reply = "IA não disponível."
            if flow_cycle:
                prompt = (
                    f"Você é um especialista sênior em cibersegurança. Analise o IP em português.\n\n"
                    f"IP: {ip} | Score: {score}/100 | País: {d.get('countryCode')} | "
                    f"ISP: {d.get('isp')} | Reportes: {d.get('totalReports')} | Tor: {d.get('isTor')}\n\n"
                    f"Responda em 3 blocos curtos:\n"
                    f"NÍVEL: (Crítico/Alto/Médio/Baixo/Seguro)\n"
                    f"PERFIL: (1 linha)\n"
                    f"AÇÃO: (bloquear/monitorar/ignorar + motivo em 1 linha)"
                )
                ai_data, _ = json_request(
                    "POST",
                    "https://flow.squareweb.app/v1/chat/completions",
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {next(flow_cycle)}"},
                    data={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": prompt}]}
                )
                ai_reply = ai_data.get("choices", [{}])[0].get("message", {}).get("content", "Sem resposta.")

            self.send_json({
                "ip":            ip,
                "score":         score,
                "country":       d.get("countryCode"),
                "isp":           d.get("isp"),
                "reports":       d.get("totalReports"),
                "isTor":         d.get("isTor"),
                "domain":        d.get("domain"),
                "lastReportedAt":d.get("lastReportedAt"),
                "ai":            ai_reply,
            }); return

        if self.path == "/api/flow":
            msg = body.get("message", "")
            if not flow_cycle:
                self.send_json({"error": "Sem chaves Flow configuradas"}, 500); return
            payload = {
                "model": "llama-3.1-8b-instant",
                "messages": [{"role": "user", "content": msg}]
            }
            req = urllib.request.Request(
                "https://flow.squareweb.app/v1/chat/completions",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {next(flow_cycle)}"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    result = json.loads(resp.read())
                reply = result.get("choices", [{}])[0].get("message", {}).get("content", "Sem resposta.")
                self.send_json({"reply": reply})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        self.send_response(404); self.end_headers()

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 80))
    print(f"✅ Match IP rodando na porta {port}")
    print(f"   AbuseIPDB keys : {len(abuse_keys)}")
    print(f"   Flow keys      : {len(flow_keys)}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
