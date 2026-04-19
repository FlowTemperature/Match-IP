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

def do_abuse_check(ip, verbose=False):
    if not abuse_cycle:
        return {"error": "Sem chaves AbuseIPDB configuradas"}, 500
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    if verbose: url += "&verbose=true"
    return json_request("GET", url, headers={"Key": next(abuse_cycle), "Accept": "application/json"})

def do_flow(message):
    if not flow_cycle:
        return None
    data, _ = json_request(
        "POST", "https://flow.squareweb.app/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {next(flow_cycle)}"},
        data={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": message}]}
    )
    return data.get("choices", [{}])[0].get("message", {}).get("content", "Sem resposta.")

# ─── HTML ─────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>IP Shield</title>
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
.header-text p { font-size: .8rem; color: var(--text2); margin-top: 3px; }

.wrap { max-width: 820px; margin: 0 auto; padding: 32px 20px 80px; }

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
}
input[type=text]:focus {
  outline: none; border-color: var(--blue);
  box-shadow: 0 0 0 3px #00aaff15;
}

.row { display: flex; gap: 10px; align-items: stretch; flex-wrap: wrap; }
.row input { flex: 1; min-width: 180px; }

.btn {
  padding: 12px 26px; border: none; border-radius: 10px;
  font-size: .92rem; font-weight: 600; cursor: pointer;
  transition: all .2s; white-space: nowrap;
}
.btn-blue {
  background: linear-gradient(135deg, #0077dd, #004ea8);
  color: #fff; border: 1px solid #0088ff66;
  box-shadow: 0 0 16px #0077dd30;
  position: relative; overflow: hidden;
}
.btn-blue::after {
  content: ''; position: absolute; top: -50%; left: -75%;
  width: 50%; height: 200%;
  background: linear-gradient(120deg, transparent, #ffffff22, transparent);
  transform: skewX(-20deg);
  animation: shimmer 2.5s infinite;
}
@keyframes shimmer { 0%{left:-75%} 100%{left:150%} }
.btn-blue:hover  { filter: brightness(1.25); transform: translateY(-2px); box-shadow: 0 4px 20px #0077dd40; }
.btn:disabled    { opacity: .4; cursor: not-allowed; transform: none !important; filter: none !important; }

.spin {
  display: inline-block; width: 14px; height: 14px;
  border: 2px solid #ffffff30; border-top-color: #fff;
  border-radius: 50%; animation: rot .7s linear infinite;
  vertical-align: middle; margin-left: 8px;
}
@keyframes rot { to { transform: rotate(360deg); } }

.rbox {
  margin-top: 20px; padding: 20px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 14px; font-size: .88rem; line-height: 1.7;
}
.rbox.ok  { border-color: #00e5a030; box-shadow: 0 0 20px #00e5a010; }
.rbox.bad { border-color: #ff446630; box-shadow: 0 0 20px #ff446610; }

.sbar-wrap { margin: 14px 0 4px; }
.sbar-labels { display: flex; justify-content: space-between; font-size: .75rem; color: var(--text2); margin-bottom: 6px; }
.sbar-bg   { height: 7px; border-radius: 99px; background: var(--bg); overflow: hidden; }
.sbar-fill { height: 100%; border-radius: 99px; transition: width .7s cubic-bezier(.4,0,.2,1); }

.badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 3px 11px; border-radius: 99px;
  font-size: .73rem; font-weight: 700; margin: 2px 3px;
  transition: transform .15s, filter .15s;
}
.badge:hover { transform: scale(1.08); filter: brightness(1.3); }
.b-green  { background: #00e5a018; color: var(--green);  border: 1px solid #00e5a035; }
.b-blue   { background: #00aaff18; color: var(--blue);   border: 1px solid #00aaff35; }
.b-red    { background: #ff446618; color: var(--red);    border: 1px solid #ff446635; }
.b-yellow { background: #ffcc0018; color: var(--yellow); border: 1px solid #ffcc0035; }
.b-gray   { background: #ffffff0c; color: var(--text2);  border: 1px solid #ffffff18; }

.ig { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 10px; margin-top: 16px; }
.ig-item {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px;
  transition: border-color .2s, transform .2s;
}
.ig-item:hover { border-color: var(--border2); transform: translateY(-2px); }
.ig-item .lbl { font-size: .68rem; color: var(--text2); text-transform: uppercase; letter-spacing: .6px; }
.ig-item .val { font-size: .9rem; font-weight: 600; margin-top: 5px; font-family: 'JetBrains Mono', monospace; }

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

.md { font-size: .88rem; line-height: 1.8; color: var(--text); }
.md h1,.md h2,.md h3 { color: var(--blue); margin: 14px 0 6px; font-size: 1rem; }
.md strong { color: var(--text); font-weight: 700; }
.md ul,.md ol { padding-left: 20px; margin: 8px 0; }
.md li { margin: 4px 0; }
.md p { margin: 6px 0; }
.md code { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; font-family: 'JetBrains Mono', monospace; font-size: .82rem; color: var(--green); }

.log {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px;
  font-size: .8rem; font-family: 'JetBrains Mono', monospace;
  max-height: 130px; overflow-y: auto; margin-top: 6px;
}
.log-row { padding: 4px 0; border-bottom: 1px solid var(--border); color: var(--text2); }
.log-row:last-child { border-bottom: none; }
.log-row span { color: var(--blue); }

a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }

.placeholder {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 12px;
  padding: 40px 20px; color: var(--text2); text-align: center;
}
.placeholder .icon { font-size: 2.8rem; opacity: .5; }
.placeholder p { font-size: .88rem; max-width: 340px; line-height: 1.6; }

/* Animações */
@keyframes fadeIn  { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
@keyframes fadeInD { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
@keyframes slideIn { from{opacity:0;transform:translateX(-12px)} to{opacity:1;transform:translateX(0)} }
@keyframes glow    { 0%,100%{box-shadow:0 0 16px #00aaff25} 50%{box-shadow:0 0 32px #00aaff55,0 0 60px #00e5a020} }

header { animation: fadeIn .6s ease; }
.wrap > .card:first-child { animation: fadeIn .7s ease; }
.logo  { animation: glow 3s ease-in-out infinite; }
.rbox  { animation: fadeInD .5s ease; }
.ai-box { animation: fadeInD .6s ease .1s both; }
.ig-item { animation: slideIn .4s ease both; }
.ig-item:nth-child(1){animation-delay:.05s}
.ig-item:nth-child(2){animation-delay:.10s}
.ig-item:nth-child(3){animation-delay:.15s}
.ig-item:nth-child(4){animation-delay:.20s}
.ig-item:nth-child(5){animation-delay:.25s}
.ig-item:nth-child(6){animation-delay:.30s}

/* Footer */
footer { text-align:center; padding:10px 0 24px; }
.footer-inner {
  display:inline-flex; align-items:center; gap:10px;
  background:linear-gradient(135deg,#030810,#050f20);
  border:1px solid #0a2040; border-radius:99px;
  padding:6px 16px; opacity:.3; transition:opacity .3s;
}
.footer-inner:hover { opacity:.85; }
.footer-by { font-size:.68rem; color:#3a6090; display:flex; align-items:center; gap:6px; }
.footer-by a {
  font-weight:600; font-size:.68rem;
  background:linear-gradient(90deg,#1a5a99,#0a8a6a);
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; text-decoration:none;
}
.footer-sep { width:1px; height:12px; background:#0d2a50; }
.footer-claude { font-size:.65rem; color:#2a4a6a; display:flex; align-items:center; gap:5px; }
.claude-badge {
  font-size:.62rem; font-weight:600;
  background:linear-gradient(135deg,#041828,#051f3a);
  border:1px solid #0d3060; border-radius:4px;
  padding:1px 7px; color:#1a5a88; letter-spacing:.2px;
}
</style>
</head>
<body>

<header>
  <div class="logo">🛡️</div>
  <div class="header-text">
    <h1>IP Shield</h1>
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

<footer>
  <div class="footer-inner">
    <div class="footer-by">
      Criado por <a href="https://github.com/FlowTemperature" target="_blank">FlowTemperature</a>
    </div>
    <div class="footer-sep"></div>
    <div class="footer-claude">
      <a href="/docs" style="color:#1a5a88;font-size:.65rem;text-decoration:none">API Docs</a>
    </div>
    <div class="footer-sep"></div>
    <div class="footer-claude">
      <a href="https://www.npmjs.com/package/@flowtemperature/matchip" target="_blank" style="color:#1a5a88;font-size:.65rem;text-decoration:none">npm</a>
    </div>
    <div class="footer-sep"></div>
    <div class="footer-claude">
      <a href="https://github.com/FlowTemperature" target="_blank" style="color:#1a5a88;font-size:.65rem;text-decoration:none">GitHub</a>
    </div>
    <div class="footer-sep"></div>
    <div class="footer-claude">com ajuda de <span class="claude-badge">Claude</span></div>
  </div>
</footer>

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
    if (j.error) { out.innerHTML = `<div class="card"><div class="rbox bad">❌ Erro: ${j.error.message||JSON.stringify(j.error)}</div></div>`; return; }
    const d = j.data, score = d.abuseConfidenceScore || 0;
    const barC = score>=75?'var(--red)':score>=30?'var(--yellow)':'var(--green)';
    const bc   = score>=75?'b-red':score>=30?'b-yellow':'b-green';
    const cls  = score>=75?'bad':'ok';
    out.innerHTML = `
    <div class="card">
      <div class="rbox ${cls}">
        <div style="display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:8px">
          <span style="font-size:1.15rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--blue)">${d.ipAddress}</span>
          <span class="badge ${bc}">${score}% abuso</span>
          ${d.isWhitelisted?'<span class="badge b-green">✓ Whitelist</span>':''}
          ${d.isTor?'<span class="badge b-red">⚠ Tor</span>':''}
          ${d.usageType?`<span class="badge b-gray">${d.usageType}</span>`:''}
        </div>
        <div class="sbar-wrap">
          <div class="sbar-labels"><span>Nível de Ameaça</span><span style="color:${barC};font-weight:700">${score}/100</span></div>
          <div class="sbar-bg"><div class="sbar-fill" style="width:${score}%;background:${barC}"></div></div>
        </div>
        <div class="ig">
          <div class="ig-item"><div class="lbl">País</div><div class="val">${d.countryCode||'N/A'} ${d.countryName||''}</div></div>
          <div class="ig-item"><div class="lbl">ISP</div><div class="val" style="font-size:.78rem">${d.isp||'N/A'}</div></div>
          <div class="ig-item"><div class="lbl">Reportes</div><div class="val">${d.totalReports}</div></div>
          <div class="ig-item"><div class="lbl">Último reporte</div><div class="val" style="font-size:.75rem">${d.lastReportedAt?new Date(d.lastReportedAt).toLocaleDateString('pt-BR'):'Nunca'}</div></div>
          <div class="ig-item"><div class="lbl">Domínio</div><div class="val" style="font-size:.78rem">${d.domain||'N/A'}</div></div>
          <div class="ig-item"><div class="lbl">Uso</div><div class="val" style="font-size:.75rem">${d.usageType||'N/A'}</div></div>
        </div>
        ${d.reports&&d.reports.length?`
        <div style="margin-top:16px;font-size:.72rem;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">📋 Últimos Reportes</div>
        <div class="log">${d.reports.slice(0,5).map(r=>`<div class="log-row"><span>[${new Date(r.reportedAt).toLocaleString('pt-BR')}]</span> ${r.comment||'sem comentário'}</div>`).join('')}</div>`:''}
        <div style="margin-top:16px"><a href="https://www.abuseipdb.com/check/${d.ipAddress}" target="_blank" class="badge b-blue">🔗 Ver no AbuseIPDB</a></div>
      </div>
      <div class="ai-box" id="ai-out">
        <div class="ai-label">Análise de IA <span class="spin" style="border-top-color:var(--green)"></span></div>
        <p style="color:var(--text2)">Gerando análise de segurança com Llama 3.1...</p>
      </div>
    </div>`;
    const ai = await fetch('/api/flow', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ message:
        `Você é um especialista sênior em cibersegurança e threat intelligence. Analise o seguinte IP com base nos dados fornecidos e entregue um relatório técnico em português brasileiro.\n\n` +
        `IP ANALISADO: ${ip}\nScore de Abuso: ${score}/100\nPaís: ${d.countryCode} — ${d.countryName||'desconhecido'}\n` +
        `ISP: ${d.isp||'desconhecido'}\nDomínio: ${d.domain||'nenhum'}\nTipo de uso: ${d.usageType||'desconhecido'}\n` +
        `Total de reportes: ${d.totalReports}\nÚltimo reporte: ${d.lastReportedAt?new Date(d.lastReportedAt).toLocaleString('pt-BR'):'nunca'}\n` +
        `Nó Tor: ${d.isTor?'SIM':'Não'}\nWhitelist: ${d.isWhitelisted?'Sim':'Não'}\n` +
        `${d.reports&&d.reports.length?'Últimos comentários:\\n'+d.reports.slice(0,3).map(r=>'• '+(r.comment||'sem comentário')).join('\\n'):''}\n\n` +
        `Responda em formato estruturado:\n🔴 NÍVEL DE AMEAÇA: (Crítico/Alto/Médio/Baixo/Seguro) — justifique em 1 linha\n` +
        `🕵️ PERFIL DO IP: O que este IP provavelmente representa\n` +
        `⚠️ RISCOS IDENTIFICADOS: Liste os principais riscos\n` +
        `🛡️ RECOMENDAÇÕES: Ações concretas para o administrador\nSeja direto, técnico e útil.`
      })
    });
    const aj = await ai.json();
    document.getElementById('ai-out').innerHTML = `<div class="ai-label">Análise de IA</div><div class="md">${marked.parse(aj.reply||aj.error||'Sem resposta.')}</div>`;
  } catch(e) {
    out.innerHTML = `<div class="card"><div class="rbox bad">❌ Erro inesperado: ${e.message}</div></div>`;
  } finally {
    btn.disabled = false; btn.innerHTML = '🔍 Analisar';
  }
}
</script>
</body>
</html>"""

HTML_BYTES = HTML.encode("utf-8")

# ─── DOCS HTML ────────────────────────────────────────────────────────────────

DOCS_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>IP Shield — API Docs</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
:root{
  --bg:#050d1a;--bg2:#071428;--bg3:#0a1e3d;
  --border:#0d3060;--border2:#1a5aaa;
  --green:#00e5a0;--green2:#00b87c;
  --blue:#00aaff;--blue2:#0066cc;
  --red:#ff4466;--yellow:#ffcc00;
  --text:#cde4ff;--text2:#6a9fd8;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;
  background-image:radial-gradient(ellipse at 15% 0%,#00aaff12 0%,transparent 55%),
  radial-gradient(ellipse at 85% 100%,#00e5a012 0%,transparent 55%)}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:10px}
header{display:flex;align-items:center;justify-content:space-between;
  padding:24px 40px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}
.logo-wrap{display:flex;align-items:center;gap:14px}
.logo{width:42px;height:42px;background:linear-gradient(135deg,var(--blue2),var(--green2));
  border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:20px}
.logo-wrap h1{font-size:1.4rem;font-weight:700;
  background:linear-gradient(90deg,var(--blue),var(--green));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-wrap span{font-size:.75rem;color:var(--text2);margin-top:2px;display:block}
.header-links{display:flex;gap:10px;flex-wrap:wrap}
.hl{padding:7px 16px;border-radius:8px;font-size:.82rem;font-weight:600;text-decoration:none;transition:.2s}
.hl-outline{border:1px solid var(--border2);color:var(--text2)}
.hl-outline:hover{border-color:var(--blue);color:var(--blue)}
.hl-fill{background:linear-gradient(135deg,var(--blue2),#004499);color:#fff;border:1px solid #0066aa55}
.hl-fill:hover{filter:brightness(1.2)}
.wrap{max-width:900px;margin:0 auto;padding:40px 24px 80px}
.hero{text-align:center;margin-bottom:48px}
.hero h2{font-size:2rem;font-weight:700;margin-bottom:10px;
  background:linear-gradient(90deg,var(--blue),var(--green));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:var(--text2);font-size:.95rem;max-width:520px;margin:0 auto;line-height:1.7}
.base-url{display:inline-flex;align-items:center;gap:10px;margin-top:18px;
  background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:10px 18px}
.base-url span{font-family:'JetBrains Mono',monospace;font-size:.88rem;color:var(--green)}
.copy-btn{background:none;border:1px solid var(--border2);border-radius:6px;
  color:var(--text2);padding:3px 10px;font-size:.72rem;cursor:pointer;transition:.2s}
.copy-btn:hover{border-color:var(--green);color:var(--green)}
.section-title{font-size:1.1rem;font-weight:700;color:var(--text);margin-bottom:16px;
  display:flex;align-items:center;gap:8px}
.section-title::before{content:'';display:inline-block;width:3px;height:18px;
  background:linear-gradient(var(--blue),var(--green));border-radius:99px}
.endpoint{background:var(--bg2);border:1px solid var(--border);border-radius:14px;
  margin-bottom:20px;overflow:hidden;position:relative}
.endpoint::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--blue),var(--green),transparent);opacity:.6}
.ep-header{padding:18px 22px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.method{font-family:'JetBrains Mono',monospace;font-size:.78rem;font-weight:700;
  padding:4px 12px;border-radius:6px;letter-spacing:.5px}
.get{background:#00aaff20;color:var(--blue);border:1px solid #00aaff40}
.post{background:#00e5a020;color:var(--green);border:1px solid #00e5a040}
.ep-path{font-family:'JetBrains Mono',monospace;font-size:.92rem;font-weight:600;color:var(--text)}
.ep-desc{color:var(--text2);font-size:.85rem;margin-left:auto}
.ep-body{padding:0 22px 22px}
.ep-body p{font-size:.85rem;color:var(--text2);margin-bottom:14px;line-height:1.6}
.label{font-size:.72rem;text-transform:uppercase;letter-spacing:.6px;
  color:var(--text2);font-weight:600;margin-bottom:8px}
pre{background:var(--bg3);border:1px solid var(--border);border-radius:10px;
  padding:14px 16px;font-family:'JetBrains Mono',monospace;font-size:.82rem;
  color:var(--text);overflow-x:auto;margin-bottom:14px;line-height:1.6}
.kw{color:var(--blue)} .str{color:var(--green)} .num{color:var(--yellow)} .key{color:var(--text2)}
.params{width:100%;border-collapse:collapse;font-size:.83rem;margin-bottom:14px}
.params th{text-align:left;padding:8px 12px;color:var(--text2);font-weight:600;
  border-bottom:1px solid var(--border);font-size:.75rem;text-transform:uppercase;letter-spacing:.5px}
.params td{padding:8px 12px;border-bottom:1px solid var(--border)}
.params tr:last-child td{border-bottom:none}
.params tr:hover td{background:#ffffff04}
.req{color:var(--red);font-size:.72rem;font-weight:700}
.opt{color:var(--text2);font-size:.72rem}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600}
.t-str{background:#00aaff15;color:var(--blue);border:1px solid #00aaff30}
.t-bool{background:#ffcc0015;color:var(--yellow);border:1px solid #ffcc0030}
.t-num{background:#00e5a015;color:var(--green);border:1px solid #00e5a030}
.divider{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:36px 0}
.cli-box{background:var(--bg3);border:1px solid var(--border);border-left:3px solid var(--green);
  border-radius:12px;padding:20px 22px;margin-bottom:20px}
.cli-box .cli-title{font-size:.72rem;text-transform:uppercase;letter-spacing:1px;
  color:var(--green);font-weight:700;margin-bottom:12px}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
footer{text-align:center;padding:10px 0 24px}
.footer-inner{display:inline-flex;align-items:center;gap:10px;
  background:linear-gradient(135deg,#030810,#050f20);border:1px solid #0a2040;
  border-radius:99px;padding:6px 16px;opacity:.35;transition:opacity .3s}
.footer-inner:hover{opacity:.85}
.footer-by{font-size:.68rem;color:#3a6090;display:flex;align-items:center;gap:6px}
.footer-by a{font-weight:600;background:linear-gradient(90deg,#1a5a99,#0a8a6a);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;text-decoration:none}
.footer-sep{width:1px;height:12px;background:#0d2a50}
.footer-claude{font-size:.65rem;color:#2a4a6a;display:flex;align-items:center;gap:5px}
.claude-badge{font-size:.62rem;font-weight:600;background:linear-gradient(135deg,#041828,#051f3a);
  border:1px solid #0d3060;border-radius:4px;padding:1px 7px;color:#1a5a88}
</style>
</head>
<body>
<header>
  <div class="logo-wrap">
    <div class="logo">🛡️</div>
    <div>
      <h1>IP Shield API</h1>
      <span>Documentação dos Endpoints</span>
    </div>
  </div>
  <div class="header-links">
    <a href="/" class="hl hl-outline">🌐 Site</a>
    <a href="https://github.com/FlowTemperature" target="_blank" class="hl hl-outline">GitHub</a>
    <a href="https://www.npmjs.com/package/@flowtemperature/matchip" target="_blank" class="hl hl-fill">📦 npm</a>
  </div>
</header>

<div class="wrap">
  <div class="hero">
    <h2>API Reference</h2>
    <p>API pública e gratuita para verificação e análise de IPs com inteligência artificial. Sem autenticação necessária.</p>
    <div class="base-url">
      <span id="base-url">https://seu-site.squareweb.app</span>
      <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('base-url').textContent);this.textContent='Copiado!';setTimeout(()=>this.textContent='Copiar',2000)">Copiar</button>
    </div>
  </div>

  <!-- ENDPOINTS -->
  <div class="section-title">Endpoints</div>

  <!-- PING -->
  <div class="endpoint">
    <div class="ep-header">
      <span class="method get">GET</span>
      <span class="ep-path">/ping</span>
      <span class="ep-desc">Health check</span>
    </div>
    <div class="ep-body">
      <p>Verifica se a API está online. Usado pela CLI para testar conectividade.</p>
      <div class="label">Resposta</div>
      <pre>{
  <span class="key">"status"</span>: <span class="str">"ok"</span>,
  <span class="key">"version"</span>: <span class="str">"1.0.0"</span>
}</pre>
      <div class="label">Exemplo</div>
      <pre><span class="kw">curl</span> https://seu-site.squareweb.app/ping</pre>
    </div>
  </div>

  <!-- CHECK -->
  <div class="endpoint">
    <div class="ep-header">
      <span class="method get">GET</span>
      <span class="ep-path">/api/check/:ip</span>
      <span class="ep-desc">Verificar IP no AbuseIPDB</span>
    </div>
    <div class="ep-body">
      <p>Retorna dados completos do IP diretamente do AbuseIPDB, incluindo score de abuso, país, ISP e últimos reportes.</p>
      <div class="label">Parâmetros</div>
      <table class="params">
        <tr><th>Nome</th><th>Tipo</th><th>Descrição</th><th></th></tr>
        <tr><td><code>ip</code></td><td><span class="tag t-str">string</span></td><td>Endereço IPv4 ou IPv6</td><td><span class="req">obrigatório</span></td></tr>
      </table>
      <div class="label">Resposta</div>
      <pre>{
  <span class="key">"data"</span>: {
    <span class="key">"ipAddress"</span>: <span class="str">"8.8.8.8"</span>,
    <span class="key">"abuseConfidenceScore"</span>: <span class="num">0</span>,
    <span class="key">"countryCode"</span>: <span class="str">"US"</span>,
    <span class="key">"countryName"</span>: <span class="str">"United States"</span>,
    <span class="key">"isp"</span>: <span class="str">"Google LLC"</span>,
    <span class="key">"domain"</span>: <span class="str">"google.com"</span>,
    <span class="key">"usageType"</span>: <span class="str">"Data Center/Web Hosting/Transit"</span>,
    <span class="key">"isTor"</span>: <span class="kw">false</span>,
    <span class="key">"isWhitelisted"</span>: <span class="kw">false</span>,
    <span class="key">"totalReports"</span>: <span class="num">0</span>,
    <span class="key">"lastReportedAt"</span>: <span class="kw">null</span>,
    <span class="key">"reports"</span>: []
  }
}</pre>
      <div class="label">Exemplo</div>
      <pre><span class="kw">curl</span> https://seu-site.squareweb.app/api/check/8.8.8.8</pre>
    </div>
  </div>

  <!-- ANALYZE -->
  <div class="endpoint">
    <div class="ep-header">
      <span class="method post">POST</span>
      <span class="ep-path">/analyze</span>
      <span class="ep-desc">Verificar IP + Análise de IA</span>
    </div>
    <div class="ep-body">
      <p>Endpoint principal da CLI. Combina os dados do AbuseIPDB com uma análise gerada por IA (Llama 3.1), retornando nível de ameaça, perfil e recomendação de ação.</p>
      <div class="label">Body (JSON)</div>
      <table class="params">
        <tr><th>Campo</th><th>Tipo</th><th>Descrição</th><th></th></tr>
        <tr><td><code>ip</code></td><td><span class="tag t-str">string</span></td><td>Endereço IPv4 ou IPv6</td><td><span class="req">obrigatório</span></td></tr>
      </table>
      <div class="label">Resposta</div>
      <pre>{
  <span class="key">"ip"</span>: <span class="str">"185.220.101.1"</span>,
  <span class="key">"score"</span>: <span class="num">100</span>,
  <span class="key">"country"</span>: <span class="str">"DE"</span>,
  <span class="key">"isp"</span>: <span class="str">"Artikel10 e.V."</span>,
  <span class="key">"domain"</span>: <span class="str">"artikel10.org"</span>,
  <span class="key">"reports"</span>: <span class="num">135</span>,
  <span class="key">"isTor"</span>: <span class="kw">true</span>,
  <span class="key">"lastReportedAt"</span>: <span class="str">"2026-04-19T00:00:00.000Z"</span>,
  <span class="key">"ai"</span>: <span class="str">"NÍVEL: Alto\\nPERFIL: Exit node Tor...\\nAÇÃO: monitorar — ..."</span>
}</pre>
      <div class="label">Exemplo</div>
      <pre><span class="kw">curl</span> -X POST https://seu-site.squareweb.app/analyze \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"ip": "185.220.101.1"}'</span></pre>
    </div>
  </div>

  <div class="divider"></div>

  <!-- CLI -->
  <div class="section-title">CLI — Match IP</div>
  <div class="cli-box">
    <div class="cli-title">📦 Instalação</div>
    <pre><span class="kw">npm</span> install -g @flowtemperature/matchip
<span class="kw">npx</span> @flowtemperature/matchip 8.8.8.8</pre>
  </div>
  <div class="cli-box">
    <div class="cli-title">💻 Uso</div>
    <pre><span class="kw">matchip</span> <span class="str">8.8.8.8</span>          <span class="key"># analisa IP</span>
<span class="kw">matchip</span> <span class="str">ping</span>             <span class="key"># verifica API</span>
<span class="kw">matchip</span> <span class="str">help</span>             <span class="key"># ajuda</span></pre>
  </div>
  <div class="cli-box">
    <div class="cli-title">🔧 Variável de ambiente</div>
    <pre><span class="kw">MATCHIP_API</span>=https://minha-api.com <span class="kw">matchip</span> 8.8.8.8</pre>
  </div>

  <div class="divider"></div>

  <!-- LIMITES -->
  <div class="section-title">Limites & Notas</div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:22px;font-size:.88rem;line-height:1.8;color:var(--text2)">
    <p>• A API é <strong style="color:var(--text)">gratuita e pública</strong> — sem autenticação, sem rate limit configurado por usuário.</p>
    <p>• Os dados de IP são fornecidos pelo <a href="https://www.abuseipdb.com" target="_blank">AbuseIPDB</a>.</p>
    <p>• A análise de IA é gerada pelo modelo <strong style="color:var(--text)">Llama 3.1 8B</strong> via Flow API.</p>
    <p>• Em caso de abuso, o acesso pode ser suspenso sem aviso prévio.</p>
    <p>• Licença: <a href="https://github.com/FlowTemperature" target="_blank">MIT</a> — use como quiser, só mantém os créditos. 🤝</p>
  </div>
</div>

<footer>
  <div class="footer-inner">
    <div class="footer-by">
      Criado por <a href="https://github.com/FlowTemperature" target="_blank">FlowTemperature</a>
    </div>
    <div class="footer-sep"></div>
    <div class="footer-claude">com ajuda de <span class="claude-badge">Claude</span></div>
  </div>
</footer>
</body>
</html>"""

# ─── Handler ──────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type",                "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length",              len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        # ── Site ──────────────────────────────────────────────────────────────
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type",   "text/html; charset=utf-8")
            self.send_header("Content-Length", len(HTML_BYTES))
            self.end_headers()
            self.wfile.write(HTML_BYTES)
            return

        # ── API: health check (CLI usa) ───────────────────────────────────────
        if self.path == "/ping":
            self.send_json({"status": "ok", "version": "1.0.0"}); return

        # ── API: check IP (site usa) ──────────────────────────────────────────
        if self.path.startswith("/api/check/"):
            ip = urllib.parse.unquote(self.path[len("/api/check/"):])
            data, status = do_abuse_check(ip, verbose=True)
            self.send_json(data, status); return

        self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}")

        # ── API: flow (site usa) ──────────────────────────────────────────────
        if self.path == "/api/flow":
            msg   = body.get("message", "")
            reply = do_flow(msg)
            self.send_json({"reply": reply or "IA não disponível."}); return

        # ── API: analyze (CLI usa) ────────────────────────────────────────────
        if self.path == "/analyze":
            ip = body.get("ip", "").strip()
            if not ip:
                self.send_json({"error": "IP obrigatório"}, 400); return

            abuse_data, _ = do_abuse_check(ip, verbose=True)
            d     = abuse_data.get("data", {})
            score = d.get("abuseConfidenceScore", 0)

            prompt = (
                f"Você é um analista sênior de threat intelligence com 15 anos de experiência. "
                f"Analise o IP abaixo com raciocínio técnico real — não seja genérico nem desconfiado sem motivo.\n\n"
                f"DADOS DO IP: {ip}\n"
                f"Score AbuseIPDB: {score}/100\n"
                f"País: {d.get('countryCode')} | ISP: {d.get('isp')} | Domínio: {d.get('domain','N/A')}\n"
                f"Tipo de uso: {d.get('usageType','desconhecido')} | Reportes: {d.get('totalReports')} | Tor: {d.get('isTor')}\n\n"
                f"REGRAS DE ANÁLISE:\n"
                f"- Score 0-10 com ISP conhecido (Google, Cloudflare, AWS, etc): provavelmente legítimo, diga isso claramente\n"
                f"- Score 0-10 com poucos reportes: considere falsos positivos antes de classificar como ameaça\n"
                f"- Score 50+: indício real de ameaça, seja direto sobre o risco\n"
                f"- Score 75+: ameaça confirmada, recomende bloqueio imediato\n"
                f"- IPs de DNS públicos (8.8.8.8, 1.1.1.1, etc): são infraestrutura legítima, trate como tal\n"
                f"- Reportes em IPs de grandes provedores podem ser falsos positivos de ferramentas automáticas\n\n"
                f"Responda EXATAMENTE neste formato, sem texto extra:\n"
                f"NÍVEL: <Crítico|Alto|Médio|Baixo|Seguro>\n"
                f"PERFIL: <1 linha descrevendo o que este IP realmente é>\n"
                f"AÇÃO: <bloquear|monitorar|ignorar> — <motivo objetivo em 1 linha>"
            )
            ai_reply = do_flow(prompt) or "IA não disponível."

            self.send_json({
                "ip":             ip,
                "score":          score,
                "country":        d.get("countryCode"),
                "isp":            d.get("isp"),
                "reports":        d.get("totalReports"),
                "isTor":          d.get("isTor"),
                "domain":         d.get("domain"),
                "lastReportedAt": d.get("lastReportedAt"),
                "ai":             ai_reply,
            }); return

        self.send_response(404); self.end_headers()

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 80))
    print(f"✅ IP Shield rodando na porta {port}")
    print(f"   Site  : GET  /")
    print(f"   CLI   : GET  /ping  |  POST /analyze")
    print(f"   AbuseIPDB keys : {len(abuse_keys)}")
    print(f"   Flow keys      : {len(flow_keys)}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
