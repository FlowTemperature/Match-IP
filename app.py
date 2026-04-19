import os
import json
import time
import itertools
import threading
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv

load_dotenv()

# ─── Rodízio de API Keys ──────────────────────────────────────────────────────

abuse_keys  = [v for k, v in sorted(os.environ.items()) if k.startswith("ABUSEIPDB_KEY_") and v]
flow_keys   = [v for k, v in sorted(os.environ.items()) if k.startswith("FLOW_KEY_") and v]
abuse_cycle = itertools.cycle(abuse_keys) if abuse_keys else None
flow_cycle  = itertools.cycle(flow_keys)  if flow_keys  else None

# ─── Blacklist em memória + arquivo ──────────────────────────────────────────

BL_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blacklist.json")
bl_lock   = threading.Lock()
blacklist = set()

def bl_load():
    global blacklist
    if os.path.exists(BL_FILE):
        try:
            with open(BL_FILE) as f:
                blacklist = set(json.load(f))
            print(f"🚫 Blacklist carregada: {len(blacklist)} IPs")
        except: blacklist = set()

def bl_save():
    with open(BL_FILE, "w") as f:
        json.dump(list(blacklist), f)

def bl_add(ip):
    with bl_lock:
        blacklist.add(ip)
        bl_save()

def bl_has(ip):
    return ip in blacklist

# ─── Rate Limit ───────────────────────────────────────────────────────────────

RATE_WINDOW  = int(os.getenv("RATE_WINDOW",  "60"))   # segundos
RATE_MAX_REQ = int(os.getenv("RATE_MAX_REQ", "30"))    # máx requests por janela
rate_lock    = threading.Lock()
rate_data    = defaultdict(list)  # ip -> [timestamps]

def rate_check(ip):
    """Retorna True se OK, False se excedeu limite."""
    now = time.time()
    with rate_lock:
        times = [t for t in rate_data[ip] if now - t < RATE_WINDOW]
        rate_data[ip] = times
        if len(times) >= RATE_MAX_REQ:
            return False
        rate_data[ip].append(now)
        return True

# ─── Helpers HTTP ─────────────────────────────────────────────────────────────

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
        return {"error": "Sem chaves AbuseIPDB"}, 500
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    if verbose: url += "&verbose=true"
    return json_request("GET", url, headers={"Key": next(abuse_cycle), "Accept": "application/json"})

def do_flow(message):
    if not flow_cycle: return None
    data, _ = json_request(
        "POST", "https://flow.squareweb.app/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {next(flow_cycle)}"},
        data={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": message}]}
    )
    return data.get("choices", [{}])[0].get("message", {}).get("content", "Sem resposta.")

# ─── Verificar visitante ──────────────────────────────────────────────────────

BLOCK_SCORE = int(os.getenv("VISITOR_BLOCK_SCORE", "25"))

def check_visitor(ip):
    """Retorna (blocked: bool, reason: str)"""
    if bl_has(ip):
        return True, "blacklist"
    if not abuse_cycle:
        return False, "ok"
    try:
        data, _ = do_abuse_check(ip)
        score   = data.get("data", {}).get("abuseConfidenceScore", 0)
        if score >= BLOCK_SCORE:
            bl_add(ip)
            print(f"🚫 IP bloqueado e salvo na blacklist: {ip} (score {score})")
            return True, f"score {score}"
        return False, "ok"
    except:
        return False, "ok"

# ─── Páginas de erro ──────────────────────────────────────────────────────────

def page_blocked():
    return """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>403</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#050d1a;color:#ff4466;
display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}
h1{font-size:5rem;background:linear-gradient(135deg,#ff4466,#ff8800);
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
p{color:#7aabdd;font-size:.95rem}a{color:#00aaff}</style></head>
<body><h1>403</h1><p>Seu IP foi identificado como malicioso e est&aacute; bloqueado.</p>
<p style="font-size:.8rem;color:#3a6090">Acredita que &eacute; um erro? <a href="https://www.abuseipdb.com" target="_blank">Verifique seu IP</a></p>
</body></html>""".encode("utf-8")

def page_ratelimit():
    return """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>429</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#050d1a;color:#ffcc00;
display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}
h1{font-size:5rem;background:linear-gradient(135deg,#ffcc00,#ff8800);
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
p{color:#7aabdd;font-size:.95rem}</style></head>
<body><h1>429</h1><p>Muitas requisi&ccedil;&otilde;es. Aguarde um momento e tente novamente.</p></body></html>""".encode("utf-8")

# ─── HTML Principal ───────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="pt-BR" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>IP Shield</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

[data-theme="dark"] {
  --bg:#050d1a;--bg2:#071428;--bg3:#0a1e3d;
  --border:#0d3060;--border2:#1a5aaa;
  --green:#00e5a0;--green2:#00b87c;
  --blue:#00aaff;--blue2:#0066cc;
  --red:#ff4466;--yellow:#ffcc00;
  --text:#cde4ff;--text2:#6a9fd8;
  --shadow:0 4px 30px #00000050;
}
[data-theme="light"] {
  --bg:#f0f4ff;--bg2:#ffffff;--bg3:#e8eeff;
  --border:#c0cef0;--border2:#6090d0;
  --green:#009966;--green2:#007a52;
  --blue:#0066cc;--blue2:#004499;
  --red:#cc2244;--yellow:#997700;
  --text:#0a1e3d;--text2:#3a5a8a;
  --shadow:0 4px 30px #00000015;
}

*{box-sizing:border-box;margin:0;padding:0;transition:background-color .3s,color .3s,border-color .3s}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;
  background-image:radial-gradient(ellipse at 15% 0%,#00aaff0a 0%,transparent 55%),
  radial-gradient(ellipse at 85% 100%,#00e5a00a 0%,transparent 55%)}
[data-theme="light"] body{background-image:radial-gradient(ellipse at 15% 0%,#0066cc08 0%,transparent 55%),
  radial-gradient(ellipse at 85% 100%,#00996608 0%,transparent 55%)}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:10px}

/* HEADER */
header{display:flex;align-items:center;justify-content:space-between;
  padding:24px 32px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px;
  position:relative}
header::after{content:'';position:absolute;bottom:-1px;left:50%;transform:translateX(-50%);
  width:200px;height:1px;background:linear-gradient(90deg,transparent,var(--blue),var(--green),transparent)}
.logo-wrap{display:flex;align-items:center;gap:14px}
.logo{width:48px;height:48px;background:linear-gradient(135deg,var(--blue2),var(--green2));
  border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:24px;
  box-shadow:0 0 24px #00aaff30;animation:glow 3s ease-in-out infinite}
@keyframes glow{0%,100%{box-shadow:0 0 16px #00aaff25}50%{box-shadow:0 0 32px #00aaff55}}
.header-text h1{font-size:1.7rem;font-weight:700;
  background:linear-gradient(90deg,var(--blue),var(--green));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header-text p{font-size:.78rem;color:var(--text2);margin-top:2px}
.header-actions{display:flex;align-items:center;gap:8px}
.theme-btn{width:38px;height:38px;border-radius:10px;border:1px solid var(--border);
  background:var(--bg2);color:var(--text2);cursor:pointer;font-size:1.1rem;
  display:flex;align-items:center;justify-content:center;transition:.2s}
.theme-btn:hover{border-color:var(--border2);color:var(--text)}
.nav-link{padding:7px 14px;border-radius:8px;font-size:.8rem;font-weight:500;
  text-decoration:none;border:1px solid var(--border);color:var(--text2);transition:.2s}
.nav-link:hover{border-color:var(--border2);color:var(--text)}

/* MAIN */
.wrap{max-width:820px;margin:0 auto;padding:28px 20px 80px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:18px;
  padding:26px;margin-bottom:16px;position:relative;overflow:hidden;box-shadow:var(--shadow)}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent 5%,var(--blue) 40%,var(--green) 60%,transparent 95%);opacity:.7}
label{display:block;font-size:.72rem;font-weight:600;color:var(--text2);
  text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
input[type=text]{width:100%;padding:12px 16px;background:var(--bg3);
  border:1px solid var(--border);border-radius:10px;color:var(--text);
  font-size:.95rem;font-family:'JetBrains Mono',monospace;
  transition:border-color .2s,box-shadow .2s}
input[type=text]:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px #00aaff15}
.row{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
.row input{flex:1;min-width:180px}

/* BUTTONS */
.btn{padding:11px 22px;border:none;border-radius:10px;font-size:.9rem;
  font-weight:600;cursor:pointer;transition:all .2s;white-space:nowrap}
.btn-blue{background:linear-gradient(135deg,#0077dd,#004ea8);color:#fff;
  border:1px solid #0088ff66;box-shadow:0 0 16px #0077dd30;position:relative;overflow:hidden}
.btn-blue::after{content:'';position:absolute;top:-50%;left:-75%;width:50%;height:200%;
  background:linear-gradient(120deg,transparent,#ffffff22,transparent);
  transform:skewX(-20deg);animation:shimmer 2.5s infinite}
@keyframes shimmer{0%{left:-75%}100%{left:150%}}
.btn-blue:hover{filter:brightness(1.25);transform:translateY(-2px)}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text2)}
.btn-outline:hover{border-color:var(--border2);color:var(--text)}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none!important;filter:none!important}

/* SPINNER */
.spin{display:inline-block;width:14px;height:14px;
  border:2px solid #ffffff30;border-top-color:#fff;
  border-radius:50%;animation:rot .7s linear infinite;vertical-align:middle;margin-left:8px}
@keyframes rot{to{transform:rotate(360deg)}}

/* RESULT */
.rbox{margin-top:20px;padding:20px;background:var(--bg3);
  border:1px solid var(--border);border-radius:14px;font-size:.88rem;line-height:1.7;
  animation:fadeInD .4s ease}
@keyframes fadeInD{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.rbox.ok{border-color:#00e5a030;box-shadow:0 0 20px #00e5a010}
.rbox.bad{border-color:#ff446630;box-shadow:0 0 20px #ff446610}
.sbar-wrap{margin:14px 0 4px}
.sbar-labels{display:flex;justify-content:space-between;font-size:.75rem;color:var(--text2);margin-bottom:6px}
.sbar-bg{height:7px;border-radius:99px;background:var(--bg);overflow:hidden}
.sbar-fill{height:100%;border-radius:99px;transition:width .7s cubic-bezier(.4,0,.2,1)}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 11px;border-radius:99px;
  font-size:.73rem;font-weight:700;margin:2px 3px;transition:transform .15s,filter .15s;cursor:default}
.badge:hover{transform:scale(1.08);filter:brightness(1.3)}
.b-green{background:#00e5a018;color:var(--green);border:1px solid #00e5a035}
.b-blue{background:#00aaff18;color:var(--blue);border:1px solid #00aaff35}
.b-red{background:#ff446618;color:var(--red);border:1px solid #ff446635}
.b-yellow{background:#ffcc0018;color:var(--yellow);border:1px solid #ffcc0035}
.b-gray{background:#ffffff0c;color:var(--text2);border:1px solid #ffffff18}
.ig{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:16px}
.ig-item{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:12px 14px;
  transition:border-color .2s,transform .2s;animation:slideIn .4s ease both}
.ig-item:hover{border-color:var(--border2);transform:translateY(-2px)}
@keyframes slideIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:translateX(0)}}
.ig-item:nth-child(1){animation-delay:.05s}.ig-item:nth-child(2){animation-delay:.10s}
.ig-item:nth-child(3){animation-delay:.15s}.ig-item:nth-child(4){animation-delay:.20s}
.ig-item:nth-child(5){animation-delay:.25s}.ig-item:nth-child(6){animation-delay:.30s}
.ig-item .lbl{font-size:.68rem;color:var(--text2);text-transform:uppercase;letter-spacing:.6px}
.ig-item .val{font-size:.9rem;font-weight:600;margin-top:5px;font-family:'JetBrains Mono',monospace}
.ai-box{margin-top:18px;padding:18px 20px;background:var(--bg);
  border:1px solid var(--border2);border-left:3px solid var(--green);border-radius:12px;
  animation:fadeInD .5s ease .1s both}
.ai-label{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--green);
  font-weight:700;display:flex;align-items:center;gap:7px;margin-bottom:10px}
.ai-label::before{content:'';display:inline-block;width:6px;height:6px;border-radius:50%;
  background:var(--green);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.md{font-size:.88rem;line-height:1.8;color:var(--text)}
.md h1,.md h2,.md h3{color:var(--blue);margin:14px 0 6px;font-size:1rem}
.md strong{color:var(--text);font-weight:700}
.md ul,.md ol{padding-left:20px;margin:8px 0}
.md li{margin:4px 0}
.md p{margin:6px 0}
.md code{background:var(--bg3);border:1px solid var(--border);border-radius:4px;
  padding:1px 6px;font-family:'JetBrains Mono',monospace;font-size:.82rem;color:var(--green)}
.log{background:var(--bg);border:1px solid var(--border);border-radius:10px;
  padding:12px 14px;font-size:.8rem;font-family:'JetBrains Mono',monospace;
  max-height:130px;overflow-y:auto;margin-top:6px}
.log-row{padding:4px 0;border-bottom:1px solid var(--border);color:var(--text2)}
.log-row:last-child{border-bottom:none}
.log-row span{color:var(--blue)}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}

/* RESULT ACTIONS */
.result-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;align-items:center}

/* HISTORY */
.hist-section{margin-top:20px}
.hist-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.6px;
  color:var(--text2);font-weight:600;margin-bottom:10px;display:flex;
  justify-content:space-between;align-items:center}
.hist-list{display:flex;flex-direction:column;gap:6px}
.hist-item{display:flex;align-items:center;gap:10px;padding:9px 12px;
  background:var(--bg3);border:1px solid var(--border);border-radius:9px;
  cursor:pointer;transition:.2s;font-size:.83rem}
.hist-item:hover{border-color:var(--border2);background:var(--bg2)}
.hist-ip{font-family:'JetBrains Mono',monospace;color:var(--blue);font-weight:600;flex:1}
.hist-score{font-size:.75rem;padding:2px 8px;border-radius:99px;font-weight:700}

/* PLACEHOLDER */
.placeholder{display:flex;flex-direction:column;align-items:center;
  justify-content:center;gap:12px;padding:40px 20px;color:var(--text2);text-align:center}
.placeholder .icon{font-size:2.8rem;opacity:.5}
.placeholder p{font-size:.88rem;max-width:340px;line-height:1.6}

/* FOOTER */
footer{text-align:center;padding:10px 0 24px}
.footer-inner{display:inline-flex;align-items:center;gap:10px;
  background:var(--bg2);border:1px solid var(--border);
  border-radius:99px;padding:6px 16px;opacity:.35;transition:opacity .3s}
.footer-inner:hover{opacity:.9}
.footer-by{font-size:.68rem;color:var(--text2);display:flex;align-items:center;gap:6px}
.footer-by a{font-weight:600;background:linear-gradient(90deg,var(--blue2),var(--green2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;text-decoration:none}
.footer-sep{width:1px;height:12px;background:var(--border2)}
.footer-link{font-size:.65rem;color:var(--text2)}
.footer-link a{color:var(--text2);text-decoration:none;transition:.2s}
.footer-link a:hover{color:var(--blue)}
.claude-badge{font-size:.62rem;font-weight:600;background:var(--bg3);
  border:1px solid var(--border);border-radius:4px;padding:1px 7px;color:var(--text2)}

/* TOAST */
.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(20px);
  background:var(--bg2);border:1px solid var(--border2);border-radius:10px;
  padding:10px 20px;font-size:.85rem;color:var(--text);
  box-shadow:0 8px 30px #00000040;opacity:0;transition:all .3s;z-index:999;pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
</style>
</head>
<body>

<header>
  <div class="logo-wrap">
    <div class="logo">🛡️</div>
    <div class="header-text">
      <h1>IP Shield</h1>
      <p>Scanner &amp; Analisador de Ameaças</p>
    </div>
  </div>
  <div class="header-actions">
    <a href="/docs" class="nav-link">API Docs</a>
    <a href="https://www.npmjs.com/package/@flowtemperature/matchip" target="_blank" class="nav-link">npm</a>
    <a href="https://github.com/FlowTemperature" target="_blank" class="nav-link">GitHub</a>
    <button class="theme-btn" id="theme-btn" onclick="toggleTheme()" title="Alternar tema">🌙</button>
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
        <p>Digite um endereço IP e clique em <strong>Analisar</strong> para ver o relatório completo com análise de IA.</p>
      </div>
      <div class="hist-section" id="hist-section" style="display:none">
        <div class="hist-title">
          <span>🕒 Histórico recente</span>
          <button class="btn btn-outline" style="padding:4px 10px;font-size:.72rem" onclick="clearHistory()">Limpar</button>
        </div>
        <div class="hist-list" id="hist-list"></div>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<footer>
  <div class="footer-inner">
    <div class="footer-by">
      Criado por <a href="https://github.com/FlowTemperature" target="_blank">FlowTemperature</a>
    </div>
    <div class="footer-sep"></div>
    <div class="footer-link"><a href="/docs">API Docs</a></div>
    <div class="footer-sep"></div>
    <div class="footer-link"><a href="https://www.npmjs.com/package/@flowtemperature/matchip" target="_blank">npm</a></div>
    <div class="footer-sep"></div>
    <div class="footer-link"><a href="https://github.com/FlowTemperature" target="_blank">GitHub</a></div>
    <div class="footer-sep"></div>
    <div class="footer-link">com ajuda de <span class="claude-badge">Claude</span></div>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script>
// ── Tema ──────────────────────────────────────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const isDark = html.getAttribute('data-theme') === 'dark';
  html.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.getElementById('theme-btn').textContent = isDark ? '🌙' : '☀️';
  localStorage.setItem('theme', isDark ? 'light' : 'dark');
}
(function(){
  const t = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('theme-btn').textContent = t === 'dark' ? '🌙' : '☀️';
  });
})();

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2500);
}

// ── Histórico ─────────────────────────────────────────────────────────────────
const HIST_KEY = 'ipshield_history';
const MAX_HIST = 10;

function histLoad() { try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]'); } catch { return []; } }
function histSave(h) { localStorage.setItem(HIST_KEY, JSON.stringify(h)); }

function histAdd(ip, score) {
  let h = histLoad().filter(x => x.ip !== ip);
  h.unshift({ ip, score, ts: Date.now() });
  if (h.length > MAX_HIST) h = h.slice(0, MAX_HIST);
  histSave(h);
  renderHistory();
}

function renderHistory() {
  const h = histLoad();
  const sec = document.getElementById('hist-section');
  const list = document.getElementById('hist-list');
  if (!h.length) { sec.style.display = 'none'; return; }
  sec.style.display = 'block';
  list.innerHTML = h.map(x => {
    const color = x.score >= 75 ? '#ff4466' : x.score >= 30 ? '#ffcc00' : '#00e5a0';
    return `<div class="hist-item" onclick="loadFromHistory('${x.ip}')">
      <span class="hist-ip">${x.ip}</span>
      <span class="hist-score" style="background:${color}20;color:${color};border:1px solid ${color}40">${x.score}/100</span>
      <span style="font-size:.72rem;color:var(--text2)">${new Date(x.ts).toLocaleDateString('pt-BR')}</span>
    </div>`;
  }).join('');
}

function clearHistory() { localStorage.removeItem(HIST_KEY); renderHistory(); toast('Histórico limpo!'); }
function loadFromHistory(ip) { document.getElementById('ip-input').value = ip; scanIP(); }

// ── Compartilhar ──────────────────────────────────────────────────────────────
function shareResult(ip) {
  const url = `${location.origin}/check/${encodeURIComponent(ip)}`;
  navigator.clipboard.writeText(url).then(() => toast('🔗 Link copiado!'));
}

// ── Copiar relatório ──────────────────────────────────────────────────────────
function copyReport(data) {
  const d = data;
  const txt = [
    `IP Shield — Relatório`,
    `IP: ${d.ipAddress}`,
    `Score: ${d.abuseConfidenceScore}/100`,
    `País: ${d.countryCode} ${d.countryName || ''}`,
    `ISP: ${d.isp || 'N/A'}`,
    `Domínio: ${d.domain || 'N/A'}`,
    `Reportes: ${d.totalReports}`,
    `Tor: ${d.isTor ? 'Sim' : 'Não'}`,
    `Último reporte: ${d.lastReportedAt ? new Date(d.lastReportedAt).toLocaleDateString('pt-BR') : 'Nunca'}`,
    ``,
    `Ver: https://www.abuseipdb.com/check/${d.ipAddress}`,
  ].join('\\n');
  navigator.clipboard.writeText(txt).then(() => toast('📋 Relatório copiado!'));
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function scanIP() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) return alert('Digite um IP!');
  const btn = document.getElementById('btn-scan');
  const out = document.getElementById('result-area');
  btn.disabled = true;
  btn.innerHTML = 'Analisando <span class="spin"></span>';
  out.innerHTML = `<div class="card"><div class="placeholder"><div class="icon">⏳</div><p>Buscando informações sobre <strong>${ip}</strong>...</p></div></div>`;

  // atualiza URL sem recarregar
  history.pushState({}, '', `/check/${encodeURIComponent(ip)}`);

  try {
    const r = await fetch('/api/check/' + encodeURIComponent(ip));
    const j = await r.json();
    if (j.error) { out.innerHTML = `<div class="card"><div class="rbox bad">❌ Erro: ${j.error.message||JSON.stringify(j.error)}</div></div>`; return; }
    const d = j.data, score = d.abuseConfidenceScore || 0;
    const barC = score>=75?'var(--red)':score>=30?'var(--yellow)':'var(--green)';
    const bc   = score>=75?'b-red':score>=30?'b-yellow':'b-green';
    const cls  = score>=75?'bad':'ok';

    histAdd(ip, score);

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
          <div class="ig-item"><div class="lbl">Último</div><div class="val" style="font-size:.75rem">${d.lastReportedAt?new Date(d.lastReportedAt).toLocaleDateString('pt-BR'):'Nunca'}</div></div>
          <div class="ig-item"><div class="lbl">Domínio</div><div class="val" style="font-size:.78rem">${d.domain||'N/A'}</div></div>
          <div class="ig-item"><div class="lbl">Uso</div><div class="val" style="font-size:.75rem">${d.usageType||'N/A'}</div></div>
        </div>
        ${d.reports&&d.reports.length?`
        <div style="margin-top:16px;font-size:.72rem;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">📋 Últimos Reportes</div>
        <div class="log">${d.reports.slice(0,5).map(r=>`<div class="log-row"><span>[${new Date(r.reportedAt).toLocaleString('pt-BR')}]</span> ${r.comment||'sem comentário'}</div>`).join('')}</div>`:''}
        <div class="result-actions">
          <a href="https://www.abuseipdb.com/check/${d.ipAddress}" target="_blank" class="badge b-blue">🔗 AbuseIPDB</a>
          <button class="btn btn-outline" style="padding:6px 14px;font-size:.78rem" onclick="copyReport(${JSON.stringify(d).replace(/'/g,"\\'")})">📋 Copiar relatório</button>
          <button class="btn btn-outline" style="padding:6px 14px;font-size:.78rem" onclick="shareResult('${d.ipAddress}')">🔗 Compartilhar</button>
        </div>
      </div>
      <div class="ai-box" id="ai-out">
        <div class="ai-label">Análise de IA <span class="spin" style="border-top-color:var(--green)"></span></div>
        <p style="color:var(--text2)">Gerando análise com Llama 3.1...</p>
      </div>
    </div>`;

    const ai = await fetch('/api/flow', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ message:
        `Você é um analista sênior de threat intelligence com 15 anos de experiência. `+
        `Analise o IP abaixo com raciocínio técnico real — não seja genérico nem desconfiado sem motivo.\n\n`+
        `DADOS DO IP: ${ip}\nScore AbuseIPDB: ${score}/100\n`+
        `País: ${d.countryCode} | ISP: ${d.isp} | Domínio: ${d.domain||'N/A'}\n`+
        `Tipo de uso: ${d.usageType||'desconhecido'} | Reportes: ${d.totalReports} | Tor: ${d.isTor}\n\n`+
        `REGRAS:\n`+
        `- Score 0-10 com ISP conhecido (Google, Cloudflare, AWS etc): provavelmente legítimo\n`+
        `- Score 0-10 com poucos reportes: considere falsos positivos\n`+
        `- Score 50+: indício real de ameaça\n`+
        `- Score 75+: ameaça confirmada, recomende bloqueio\n`+
        `- IPs de DNS públicos (8.8.8.8, 1.1.1.1): infraestrutura legítima\n\n`+
        `Responda em formato estruturado:\n`+
        `🔴 NÍVEL DE AMEAÇA: (Crítico/Alto/Médio/Baixo/Seguro) — justifique em 1 linha\n`+
        `🕵️ PERFIL DO IP: O que este IP realmente é\n`+
        `⚠️ RISCOS: Liste os principais riscos\n`+
        `🛡️ RECOMENDAÇÕES: Ações concretas\nSeja direto e técnico.`
      })
    });
    const aj = await ai.json();
    document.getElementById('ai-out').innerHTML =
      `<div class="ai-label">Análise de IA</div><div class="md">${marked.parse(aj.reply||aj.error||'Sem resposta.')}</div>`;
  } catch(e) {
    out.innerHTML = `<div class="card"><div class="rbox bad">❌ Erro: ${e.message}</div></div>`;
  } finally {
    btn.disabled = false; btn.innerHTML = '🔍 Analisar';
  }
}

// ── Carregar IP da URL ────────────────────────────────────────────────────────
(function(){
  renderHistory();
  const m = location.pathname.match(/^\\/check\\/(.+)$/);
  if (m) {
    const ip = decodeURIComponent(m[1]);
    document.getElementById('ip-input').value = ip;
    scanIP();
  }
})();
</script>
</body>
</html>"""

HTML_BYTES = HTML.encode("utf-8")
