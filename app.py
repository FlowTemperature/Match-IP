import sys
import traceback
sys.stderr = sys.stdout

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

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

print("✅ Imports OK")

# ─── Rodízio de API Keys ──────────────────────────────────────────────────────

abuse_keys  = [v for k, v in sorted(os.environ.items()) if k.startswith("ABUSEIPDB_KEY_") and v]
flow_keys   = [v for k, v in sorted(os.environ.items()) if k.startswith("FLOW_KEY_") and v]
abuse_cycle = itertools.cycle(abuse_keys) if abuse_keys else None
flow_cycle  = itertools.cycle(flow_keys)  if flow_keys  else None
print(f"✅ Keys OK — abuse:{len(abuse_keys)} flow:{len(flow_keys)}")

# ─── Blacklist em memória + arquivo ──────────────────────────────────────────

try:
    _base = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _base = os.getcwd()

BL_FILE   = os.path.join(_base, "blacklist.json")
bl_lock   = threading.Lock()
blacklist = set()

def bl_load():
    global blacklist
    if os.path.exists(BL_FILE):
        try:
            with open(BL_FILE) as f:
                blacklist = set(json.load(f))
            print(f"🚫 Blacklist carregada: {len(blacklist)} IPs")
        except Exception:
            blacklist = set()

def bl_save():
    try:
        with open(BL_FILE, "w") as f:
            json.dump(list(blacklist), f)
    except Exception as e:
        print(f"⚠️  bl_save erro: {e}")

def bl_add(ip):
    with bl_lock:
        blacklist.add(ip)
        bl_save()

def bl_has(ip):
    return ip in blacklist

bl_load()
print("✅ Blacklist OK")

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
    if verbose:
        url += "&verbose=true"
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

# ─── Verificar visitante ──────────────────────────────────────────────────────

BLOCK_SCORE = int(os.getenv("VISITOR_BLOCK_SCORE", "25"))

def check_visitor(ip):
    """Retorna (blocked: bool, reason: str). Bane IPs com score >= BLOCK_SCORE."""
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
    except Exception:
        return False, "ok"

# ─── Páginas de erro ──────────────────────────────────────────────────────────

def page_blocked():
    return (
        b"<!DOCTYPE html><html><head><meta charset='UTF-8'><title>403</title>"
        b"<style>*{margin:0;padding:0;box-sizing:border-box}"
        b"body{font-family:sans-serif;background:#050d1a;color:#ff4466;"
        b"display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}"
        b"h1{font-size:5rem;background:linear-gradient(135deg,#ff4466,#ff8800);"
        b"-webkit-background-clip:text;-webkit-text-fill-color:transparent}"
        b"p{color:#7aabdd;font-size:.95rem}a{color:#00aaff}</style></head>"
        b"<body><h1>403</h1><p>Seu IP foi identificado como malicioso e est&aacute; bloqueado.</p>"
        b"<p style='font-size:.8rem;color:#3a6090'>Acredita que &eacute; um erro? "
        b"<a href='https://www.abuseipdb.com' target='_blank'>Verifique seu IP</a></p>"
        b"</body></html>"
    )

def page_ratelimit():
    return (
        b"<!DOCTYPE html><html><head><meta charset='UTF-8'><title>429</title>"
        b"<style>*{margin:0;padding:0;box-sizing:border-box}"
        b"body{font-family:sans-serif;background:#050d1a;color:#ffcc00;"
        b"display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}"
        b"h1{font-size:5rem;background:linear-gradient(135deg,#ffcc00,#ff8800);"
        b"-webkit-background-clip:text;-webkit-text-fill-color:transparent}"
        b"p{color:#7aabdd;font-size:.95rem}</style></head>"
        b"<body><h1>429</h1><p>Muitas requisi&ccedil;&otilde;es. Aguarde um momento.</p></body></html>"
    )

# ─── HTML Principal (bytes literais — sem risco de encoding) ─────────────────

HTML = (
    b"<!DOCTYPE html>\n"
    b"<html lang='pt-BR'>\n"
    b"<head>\n"
    b"<meta charset='UTF-8'/>\n"
    b"<meta name='viewport' content='width=device-width,initial-scale=1'/>\n"
    b"<title>Match IP</title>\n"
    b"<style>\n"
    b"@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');\n"
    b":root {\n"
    b"  --bg:#050d1a;--bg2:#071428;--bg3:#0a1e3d;\n"
    b"  --border:#0d3060;--border2:#1a5aaa;\n"
    b"  --green:#00e5a0;--green2:#00b87c;\n"
    b"  --blue:#00aaff;--blue2:#0066cc;\n"
    b"  --red:#ff4466;--yellow:#ffcc00;\n"
    b"  --text:#cde4ff;--text2:#6a9fd8;\n"
    b"}\n"
    b"* { box-sizing:border-box; margin:0; padding:0; }\n"
    b"body { font-family:'Inter',sans-serif; background:var(--bg); color:var(--text); min-height:100vh;\n"
    b"  background-image: radial-gradient(ellipse at 15% 0%,#00aaff12 0%,transparent 55%),\n"
    b"  radial-gradient(ellipse at 85% 100%,#00e5a012 0%,transparent 55%); }\n"
    b"::-webkit-scrollbar{width:5px} ::-webkit-scrollbar-track{background:var(--bg2)}\n"
    b"::-webkit-scrollbar-thumb{background:var(--border2);border-radius:10px}\n"
    b"header{display:flex;align-items:center;justify-content:center;gap:16px;\n"
    b"  padding:32px 24px 24px;border-bottom:1px solid var(--border);position:relative;}\n"
    b"header::after{content:'';position:absolute;bottom:-1px;left:50%;transform:translateX(-50%);\n"
    b"  width:200px;height:1px;background:linear-gradient(90deg,transparent,var(--blue),var(--green),transparent);}\n"
    b".logo{width:52px;height:52px;background:linear-gradient(135deg,var(--blue2),var(--green2));\n"
    b"  border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:26px;\n"
    b"  box-shadow:0 0 24px #00aaff30,0 4px 12px #00000040;animation:glow 3s ease-in-out infinite;}\n"
    b".header-text h1{font-size:1.9rem;font-weight:700;\n"
    b"  background:linear-gradient(90deg,var(--blue),var(--green));\n"
    b"  -webkit-background-clip:text;-webkit-text-fill-color:transparent;}\n"
    b".header-text p{font-size:.8rem;color:var(--text2);margin-top:3px;}\n"
    b".wrap{max-width:820px;margin:0 auto;padding:32px 20px 80px;}\n"
    b".card{background:var(--bg2);border:1px solid var(--border);border-radius:18px;\n"
    b"  padding:28px;margin-bottom:18px;position:relative;overflow:hidden;box-shadow:0 4px 30px #00000030;}\n"
    b".card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;\n"
    b"  background:linear-gradient(90deg,transparent 5%,var(--blue) 40%,var(--green) 60%,transparent 95%);opacity:.7;}\n"
    b"label{display:block;font-size:.72rem;font-weight:600;color:var(--text2);\n"
    b"  text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;}\n"
    b"input[type=text]{width:100%;padding:12px 16px;background:var(--bg3);border:1px solid var(--border);\n"
    b"  border-radius:10px;color:var(--text);font-size:.95rem;font-family:'JetBrains Mono',monospace;\n"
    b"  transition:border-color .2s,box-shadow .2s;}\n"
    b"input[type=text]:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px #00aaff15;}\n"
    b".row{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap;}\n"
    b".row input{flex:1;min-width:180px;}\n"
    b".btn{padding:12px 26px;border:none;border-radius:10px;font-size:.92rem;font-weight:600;\n"
    b"  cursor:pointer;transition:all .2s;white-space:nowrap;}\n"
    b".btn-blue{background:linear-gradient(135deg,#0077dd,#004ea8);color:#fff;\n"
    b"  border:1px solid #0088ff66;box-shadow:0 0 16px #0077dd30;position:relative;overflow:hidden;}\n"
    b".btn-blue::after{content:'';position:absolute;top:-50%;left:-75%;width:50%;height:200%;\n"
    b"  background:linear-gradient(120deg,transparent,#ffffff22,transparent);\n"
    b"  transform:skewX(-20deg);animation:shimmer 2.5s infinite;}\n"
    b"@keyframes shimmer{0%{left:-75%}100%{left:150%}}\n"
    b".btn-blue:hover{filter:brightness(1.25);transform:translateY(-2px);}\n"
    b".btn:disabled{opacity:.4;cursor:not-allowed;transform:none!important;filter:none!important;}\n"
    b".spin{display:inline-block;width:14px;height:14px;\n"
    b"  border:2px solid #ffffff30;border-top-color:#fff;\n"
    b"  border-radius:50%;animation:rot .7s linear infinite;vertical-align:middle;margin-left:8px;}\n"
    b"@keyframes rot{to{transform:rotate(360deg)}}\n"
    b".rbox{margin-top:20px;padding:20px;background:var(--bg3);border:1px solid var(--border);\n"
    b"  border-radius:14px;font-size:.88rem;line-height:1.7;animation:fadeInD .5s ease;}\n"
    b".rbox.ok{border-color:#00e5a030;box-shadow:0 0 20px #00e5a010;}\n"
    b".rbox.bad{border-color:#ff446630;box-shadow:0 0 20px #ff446610;}\n"
    b".sbar-wrap{margin:14px 0 4px;}\n"
    b".sbar-labels{display:flex;justify-content:space-between;font-size:.75rem;color:var(--text2);margin-bottom:6px;}\n"
    b".sbar-bg{height:7px;border-radius:99px;background:var(--bg);overflow:hidden;}\n"
    b".sbar-fill{height:100%;border-radius:99px;transition:width .7s cubic-bezier(.4,0,.2,1);}\n"
    b".badge{display:inline-flex;align-items:center;gap:4px;padding:3px 11px;border-radius:99px;\n"
    b"  font-size:.73rem;font-weight:700;margin:2px 3px;transition:transform .15s,filter .15s;}\n"
    b".badge:hover{transform:scale(1.08);filter:brightness(1.3);}\n"
    b".b-green{background:#00e5a018;color:var(--green);border:1px solid #00e5a035;}\n"
    b".b-blue{background:#00aaff18;color:var(--blue);border:1px solid #00aaff35;}\n"
    b".b-red{background:#ff446618;color:var(--red);border:1px solid #ff446635;}\n"
    b".b-yellow{background:#ffcc0018;color:var(--yellow);border:1px solid #ffcc0035;}\n"
    b".b-gray{background:#ffffff0c;color:var(--text2);border:1px solid #ffffff18;}\n"
    b".ig{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:16px;}\n"
    b".ig-item{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:12px 14px;\n"
    b"  transition:border-color .2s,transform .2s;animation:slideIn .4s ease both;}\n"
    b".ig-item:hover{border-color:var(--border2);transform:translateY(-2px);}\n"
    b".ig-item .lbl{font-size:.68rem;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;}\n"
    b".ig-item .val{font-size:.9rem;font-weight:600;margin-top:5px;font-family:'JetBrains Mono',monospace;}\n"
    b".ig-item:nth-child(1){animation-delay:.05s}.ig-item:nth-child(2){animation-delay:.10s}\n"
    b".ig-item:nth-child(3){animation-delay:.15s}.ig-item:nth-child(4){animation-delay:.20s}\n"
    b".ig-item:nth-child(5){animation-delay:.25s}.ig-item:nth-child(6){animation-delay:.30s}\n"
    b".ai-box{margin-top:18px;padding:18px 20px;background:#030c1c;\n"
    b"  border:1px solid #1a4a8a;border-left:3px solid var(--green);border-radius:12px;}\n"
    b".ai-label{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--green);\n"
    b"  font-weight:700;display:flex;align-items:center;gap:7px;margin-bottom:10px;}\n"
    b".ai-label::before{content:'';display:inline-block;width:6px;height:6px;border-radius:50%;\n"
    b"  background:var(--green);animation:pulse 1.5s infinite;}\n"
    b"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}\n"
    b".md{font-size:.88rem;line-height:1.8;color:var(--text);}\n"
    b".md h1,.md h2,.md h3{color:var(--blue);margin:14px 0 6px;font-size:1rem;}\n"
    b".md strong{color:var(--text);font-weight:700;}\n"
    b".md ul,.md ol{padding-left:20px;margin:8px 0;} .md li{margin:4px 0;} .md p{margin:6px 0;}\n"
    b".md code{background:var(--bg3);border:1px solid var(--border);border-radius:4px;\n"
    b"  padding:1px 6px;font-family:'JetBrains Mono',monospace;font-size:.82rem;color:var(--green);}\n"
    b".log{background:var(--bg);border:1px solid var(--border);border-radius:10px;\n"
    b"  padding:12px 14px;font-size:.8rem;font-family:'JetBrains Mono',monospace;\n"
    b"  max-height:130px;overflow-y:auto;margin-top:6px;}\n"
    b".log-row{padding:4px 0;border-bottom:1px solid var(--border);color:var(--text2);}\n"
    b".log-row:last-child{border-bottom:none;} .log-row span{color:var(--blue);}\n"
    b"a{color:var(--blue);text-decoration:none;} a:hover{text-decoration:underline;}\n"
    b".placeholder{display:flex;flex-direction:column;align-items:center;\n"
    b"  justify-content:center;gap:12px;padding:40px 20px;color:var(--text2);text-align:center;}\n"
    b".placeholder .icon{font-size:2.8rem;opacity:.5;}\n"
    b".placeholder p{font-size:.88rem;max-width:340px;line-height:1.6;}\n"
    b"@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}\n"
    b"@keyframes fadeInD{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}\n"
    b"@keyframes slideIn{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:translateX(0)}}\n"
    b"@keyframes glow{0%,100%{box-shadow:0 0 16px #00aaff25}50%{box-shadow:0 0 32px #00aaff55,0 0 60px #00e5a020}}\n"
    b"header{animation:fadeIn .6s ease;} .wrap>.card:first-child{animation:fadeIn .7s ease;}\n"
    b".rbox{animation:fadeInD .5s ease;} .ai-box{animation:fadeInD .6s ease .1s both;}\n"
    b".ig-item{animation:slideIn .4s ease both;}\n"
    b"footer{text-align:center;padding:10px 0 24px;}\n"
    b".footer-inner{display:inline-flex;align-items:center;gap:10px;\n"
    b"  background:linear-gradient(135deg,#030810,#050f20);\n"
    b"  border:1px solid #0a2040;border-radius:99px;padding:6px 16px;opacity:.3;transition:opacity .3s;}\n"
    b".footer-inner:hover{opacity:.85;}\n"
    b".footer-by{font-size:.68rem;color:#3a6090;display:flex;align-items:center;gap:6px;}\n"
    b".footer-by a{font-weight:600;background:linear-gradient(90deg,#1a5a99,#0a8a6a);\n"
    b"  -webkit-background-clip:text;-webkit-text-fill-color:transparent;text-decoration:none;}\n"
    b".footer-sep{width:1px;height:12px;background:#0d2a50;}\n"
    b".footer-claude{font-size:.65rem;color:#2a4a6a;display:flex;align-items:center;gap:5px;}\n"
    b".claude-badge{font-size:.62rem;font-weight:600;background:linear-gradient(135deg,#041828,#051f3a);\n"
    b"  border:1px solid #0d3060;border-radius:4px;padding:1px 7px;color:#1a5a88;}\n"
    b"</style>\n"
    b"</head>\n"
    b"<body>\n"
    b"<header>\n"
    b"  <div class='logo'>&#x1F6E1;&#xFE0F;</div>\n"
    b"  <div class='header-text'>\n"
    b"    <h1>Match IP</h1>\n"
    b"    <p>Scanner &amp; Analisador de Amea&ccedil;as em Tempo Real</p>\n"
    b"  </div>\n"
    b"</header>\n"
    b"<div class='wrap'>\n"
    b"  <div class='card'>\n"
    b"    <label>Endere&ccedil;o IP</label>\n"
    b"    <div class='row'>\n"
    b"      <input type='text' id='ip-input' placeholder='Ex: 8.8.8.8 ou 185.220.101.1'\n"
    b"             onkeydown=\"if(event.key==='Enter')scanIP()\"/>\n"
    b"      <button class='btn btn-blue' id='btn-scan' onclick='scanIP()'>&#x1F50D; Analisar</button>\n"
    b"    </div>\n"
    b"  </div>\n"
    b"  <div id='result-area'>\n"
    b"    <div class='card'>\n"
    b"      <div class='placeholder'>\n"
    b"        <div class='icon'>&#x1F310;</div>\n"
    b"        <p>Digite um endere&ccedil;o IP acima e clique em <strong>Analisar</strong> para ver o relat&oacute;rio completo com an&aacute;lise de IA.</p>\n"
    b"      </div>\n"
    b"    </div>\n"
    b"  </div>\n"
    b"</div>\n"
    b"<footer>\n"
    b"  <div class='footer-inner'>\n"
    b"    <div class='footer-by'>Criado por <a href='https://github.com/FlowTemperature' target='_blank'>FlowTemperature</a></div>\n"
    b"    <div class='footer-sep'></div>\n"
    b"    <div class='footer-claude'><a href='/docs' style='color:#1a5a88;font-size:.65rem;text-decoration:none'>API Docs</a></div>\n"
    b"    <div class='footer-sep'></div>\n"
    b"    <div class='footer-claude'><a href='https://www.npmjs.com/package/@flowtemperature/matchip' target='_blank' style='color:#1a5a88;font-size:.65rem;text-decoration:none'>npm</a></div>\n"
    b"    <div class='footer-sep'></div>\n"
    b"    <div class='footer-claude'><a href='https://github.com/FlowTemperature' target='_blank' style='color:#1a5a88;font-size:.65rem;text-decoration:none'>GitHub</a></div>\n"
    b"    <div class='footer-sep'></div>\n"
    b"    <div class='footer-claude'>com ajuda de <span class='claude-badge'>Claude</span></div>\n"
    b"  </div>\n"
    b"</footer>\n"
    b"<script src='https://cdn.jsdelivr.net/npm/marked/marked.min.js'></script>\n"
    b"<script>\n"
    b"async function scanIP() {\n"
    b"  const ip  = document.getElementById('ip-input').value.trim();\n"
    b"  if (!ip)  return alert('Digite um endere\\u00e7o IP!');\n"
    b"  const btn = document.getElementById('btn-scan');\n"
    b"  const out = document.getElementById('result-area');\n"
    b"  btn.disabled = true;\n"
    b"  btn.innerHTML = 'Analisando <span class=\"spin\"></span>';\n"
    b"  out.innerHTML = `<div class=\"card\"><div class=\"placeholder\"><div class=\"icon\">&#x23F3;</div><p>Buscando informa\\u00e7\\u00f5es sobre <strong>${ip}</strong>...</p></div></div>`;\n"
    b"  try {\n"
    b"    const r = await fetch('/api/check/' + encodeURIComponent(ip));\n"
    b"    const j = await r.json();\n"
    b"    if (j.error) { out.innerHTML = `<div class=\"card\"><div class=\"rbox bad\">&#x274C; Erro: ${j.error.message||JSON.stringify(j.error)}</div></div>`; return; }\n"
    b"    const d = j.data, score = d.abuseConfidenceScore || 0;\n"
    b"    const barC = score>=75?'var(--red)':score>=30?'var(--yellow)':'var(--green)';\n"
    b"    const bc   = score>=75?'b-red':score>=30?'b-yellow':'b-green';\n"
    b"    const cls  = score>=75?'bad':'ok';\n"
    b"    out.innerHTML = `\n"
    b"    <div class=\"card\">\n"
    b"      <div class=\"rbox ${cls}\">\n"
    b"        <div style=\"display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:8px\">\n"
    b"          <span style=\"font-size:1.15rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--blue)\">${d.ipAddress}</span>\n"
    b"          <span class=\"badge ${bc}\">${score}% abuso</span>\n"
    b"          ${d.isWhitelisted?'<span class=\"badge b-green\">&#x2713; Whitelist</span>':''}\n"
    b"          ${d.isTor?'<span class=\"badge b-red\">&#x26A0; Tor</span>':''}\n"
    b"          ${d.usageType?`<span class=\"badge b-gray\">${d.usageType}</span>`:''}\n"
    b"        </div>\n"
    b"        <div class=\"sbar-wrap\">\n"
    b"          <div class=\"sbar-labels\"><span>N\\u00edvel de Amea\\u00e7a</span><span style=\"color:${barC};font-weight:700\">${score}/100</span></div>\n"
    b"          <div class=\"sbar-bg\"><div class=\"sbar-fill\" style=\"width:${score}%;background:${barC}\"></div></div>\n"
    b"        </div>\n"
    b"        <div class=\"ig\">\n"
    b"          <div class=\"ig-item\"><div class=\"lbl\">Pa\\u00eds</div><div class=\"val\">${d.countryCode||'N/A'} ${d.countryName||''}</div></div>\n"
    b"          <div class=\"ig-item\"><div class=\"lbl\">ISP</div><div class=\"val\" style=\"font-size:.78rem\">${d.isp||'N/A'}</div></div>\n"
    b"          <div class=\"ig-item\"><div class=\"lbl\">Reportes</div><div class=\"val\">${d.totalReports}</div></div>\n"
    b"          <div class=\"ig-item\"><div class=\"lbl\">\\u00daltimo reporte</div><div class=\"val\" style=\"font-size:.75rem\">${d.lastReportedAt?new Date(d.lastReportedAt).toLocaleDateString('pt-BR'):'Nunca'}</div></div>\n"
    b"          <div class=\"ig-item\"><div class=\"lbl\">Dom\\u00ednio</div><div class=\"val\" style=\"font-size:.78rem\">${d.domain||'N/A'}</div></div>\n"
    b"          <div class=\"ig-item\"><div class=\"lbl\">Uso</div><div class=\"val\" style=\"font-size:.75rem\">${d.usageType||'N/A'}</div></div>\n"
    b"        </div>\n"
    b"        ${d.reports&&d.reports.length?`\n"
    b"        <div style=\"margin-top:16px;font-size:.72rem;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px\">&#x1F4CB; \\u00daltimos Reportes</div>\n"
    b"        <div class=\"log\">${d.reports.slice(0,5).map(r=>`<div class=\"log-row\"><span>[${new Date(r.reportedAt).toLocaleString('pt-BR')}]</span> ${r.comment||'sem coment\\u00e1rio'}</div>`).join('')}</div>`:''}\n"
    b"        <div style=\"margin-top:16px\"><a href=\"https://www.abuseipdb.com/check/${d.ipAddress}\" target=\"_blank\" class=\"badge b-blue\">&#x1F517; Ver no AbuseIPDB</a></div>\n"
    b"      </div>\n"
    b"      <div class=\"ai-box\" id=\"ai-out\">\n"
    b"        <div class=\"ai-label\">An\\u00e1lise de IA <span class=\"spin\" style=\"border-top-color:var(--green)\"></span></div>\n"
    b"        <p style=\"color:var(--text2)\">Gerando an\\u00e1lise de seguran\\u00e7a com Llama 3.1...</p>\n"
    b"      </div>\n"
    b"    </div>`;\n"
    b"    const ai = await fetch('/api/flow', {\n"
    b"      method:'POST', headers:{'Content-Type':'application/json'},\n"
    b"      body: JSON.stringify({ message:\n"
    b"        'Voc\\u00ea \\u00e9 um especialista s\\u00eanior em ciberseguran\\u00e7a e threat intelligence. ' +\n"
    b"        'Analise o seguinte IP com base nos dados fornecidos e entregue um relat\\u00f3rio t\\u00e9cnico em portugu\\u00eas brasileiro.\\n\\n' +\n"
    b"        'IP ANALISADO: ' + ip + '\\nScore de Abuso: ' + score + '/100\\n' +\n"
    b"        'Pa\\u00eds: ' + d.countryCode + ' | ISP: ' + d.isp + ' | Dom\\u00ednio: ' + (d.domain||'N/A') + '\\n' +\n"
    b"        'Tipo de uso: ' + (d.usageType||'desconhecido') + ' | Reportes: ' + d.totalReports + ' | Tor: ' + d.isTor + '\\n\\n' +\n"
    b"        'Responda em formato estruturado:\\n' +\n"
    b"        '\\ud83d\\udd34 N\\u00cdVEL DE AMEA\\u00c7A: (Cr\\u00edtico/Alto/M\\u00e9dio/Baixo/Seguro) \\u2014 justifique em 1 linha\\n' +\n"
    b"        '\\ud83d\\udd75\\ufe0f PERFIL DO IP: O que este IP provavelmente representa\\n' +\n"
    b"        '\\u26a0\\ufe0f RISCOS IDENTIFICADOS: Liste os principais riscos\\n' +\n"
    b"        '\\ud83d\\udee1\\ufe0f RECOMENDA\\u00c7\\u00d5ES: A\\u00e7\\u00f5es concretas para o administrador\\nSeja direto, t\\u00e9cnico e \\u00fatil.'\n"
    b"      })\n"
    b"    });\n"
    b"    const aj = await ai.json();\n"
    b"    document.getElementById('ai-out').innerHTML = `<div class=\"ai-label\">An\\u00e1lise de IA</div><div class=\"md\">${marked.parse(aj.reply||aj.error||'Sem resposta.')}</div>`;\n"
    b"  } catch(e) {\n"
    b"    out.innerHTML = `<div class=\"card\"><div class=\"rbox bad\">&#x274C; Erro inesperado: ${e.message}</div></div>`;\n"
    b"  } finally {\n"
    b"    btn.disabled = false; btn.innerHTML = '&#x1F50D; Analisar';\n"
    b"  }\n"
    b"}\n"
    b"</script>\n"
    b"</body>\n"
    b"</html>\n"
)

# ─── DOCS HTML ────────────────────────────────────────────────────────────────

DOCS_HTML = (
    b"<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'/>"
    b"<meta name='viewport' content='width=device-width,initial-scale=1'/>"
    b"<title>Match IP &mdash; API Docs</title>"
    b"<style>"
    b"@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');"
    b":root{--bg:#050d1a;--bg2:#071428;--bg3:#0a1e3d;--border:#0d3060;--border2:#1a5aaa;"
    b"--green:#00e5a0;--blue:#00aaff;--blue2:#0066cc;--red:#ff4466;--yellow:#ffcc00;--text:#cde4ff;--text2:#6a9fd8;}"
    b"*{box-sizing:border-box;margin:0;padding:0}"
    b"body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;"
    b"background-image:radial-gradient(ellipse at 15% 0%,#00aaff12 0%,transparent 55%),"
    b"radial-gradient(ellipse at 85% 100%,#00e5a012 0%,transparent 55%)}"
    b"::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--bg2)}"
    b"::-webkit-scrollbar-thumb{background:var(--border2);border-radius:10px}"
    b"header{display:flex;align-items:center;justify-content:space-between;"
    b"padding:24px 40px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}"
    b".logo-wrap{display:flex;align-items:center;gap:14px}"
    b".logo{width:42px;height:42px;background:linear-gradient(135deg,var(--blue2),#00b87c);"
    b"border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:20px}"
    b".logo-wrap h1{font-size:1.4rem;font-weight:700;"
    b"background:linear-gradient(90deg,var(--blue),var(--green));"
    b"-webkit-background-clip:text;-webkit-text-fill-color:transparent}"
    b".logo-wrap span{font-size:.75rem;color:var(--text2);display:block}"
    b".header-links{display:flex;gap:10px;flex-wrap:wrap}"
    b".hl{padding:7px 16px;border-radius:8px;font-size:.82rem;font-weight:600;text-decoration:none;transition:.2s}"
    b".hl-outline{border:1px solid var(--border2);color:var(--text2)}"
    b".hl-outline:hover{border-color:var(--blue);color:var(--blue)}"
    b".hl-fill{background:linear-gradient(135deg,var(--blue2),#004499);color:#fff;border:1px solid #0066aa55}"
    b".hl-fill:hover{filter:brightness(1.2)}"
    b".wrap{max-width:900px;margin:0 auto;padding:40px 24px 80px}"
    b".hero{text-align:center;margin-bottom:48px}"
    b".hero h2{font-size:2rem;font-weight:700;margin-bottom:10px;"
    b"background:linear-gradient(90deg,var(--blue),var(--green));"
    b"-webkit-background-clip:text;-webkit-text-fill-color:transparent}"
    b".hero p{color:var(--text2);font-size:.95rem;max-width:520px;margin:0 auto;line-height:1.7}"
    b".base-url{display:inline-flex;align-items:center;gap:10px;margin-top:18px;"
    b"background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:10px 18px}"
    b".base-url span{font-family:'JetBrains Mono',monospace;font-size:.88rem;color:var(--green)}"
    b".copy-btn{background:none;border:1px solid var(--border2);border-radius:6px;"
    b"color:var(--text2);padding:3px 10px;font-size:.72rem;cursor:pointer;transition:.2s}"
    b".copy-btn:hover{border-color:var(--green);color:var(--green)}"
    b".section-title{font-size:1.1rem;font-weight:700;color:var(--text);margin-bottom:16px;"
    b"display:flex;align-items:center;gap:8px}"
    b".section-title::before{content:'';display:inline-block;width:3px;height:18px;"
    b"background:linear-gradient(var(--blue),var(--green));border-radius:99px}"
    b".endpoint{background:var(--bg2);border:1px solid var(--border);border-radius:14px;"
    b"margin-bottom:20px;overflow:hidden;position:relative}"
    b".endpoint::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;"
    b"background:linear-gradient(90deg,transparent,var(--blue),var(--green),transparent);opacity:.6}"
    b".ep-header{padding:18px 22px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}"
    b".method{font-family:'JetBrains Mono',monospace;font-size:.78rem;font-weight:700;"
    b"padding:4px 12px;border-radius:6px;letter-spacing:.5px}"
    b".get{background:#00aaff20;color:var(--blue);border:1px solid #00aaff40}"
    b".post{background:#00e5a020;color:var(--green);border:1px solid #00e5a040}"
    b".ep-path{font-family:'JetBrains Mono',monospace;font-size:.92rem;font-weight:600;color:var(--text)}"
    b".ep-desc{color:var(--text2);font-size:.85rem;margin-left:auto}"
    b".ep-body{padding:0 22px 22px}"
    b".ep-body p{font-size:.85rem;color:var(--text2);margin-bottom:14px;line-height:1.6}"
    b".lbl2{font-size:.72rem;text-transform:uppercase;letter-spacing:.6px;color:var(--text2);font-weight:600;margin-bottom:8px}"
    b"pre{background:var(--bg3);border:1px solid var(--border);border-radius:10px;"
    b"padding:14px 16px;font-family:'JetBrains Mono',monospace;font-size:.82rem;"
    b"color:var(--text);overflow-x:auto;margin-bottom:14px;line-height:1.6}"
    b".kw{color:var(--blue)}.str{color:var(--green)}.key{color:var(--text2)}"
    b".divider{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:36px 0}"
    b".cli-box{background:var(--bg3);border:1px solid var(--border);border-left:3px solid var(--green);"
    b"border-radius:12px;padding:20px 22px;margin-bottom:20px}"
    b".cli-title{font-size:.72rem;text-transform:uppercase;letter-spacing:1px;"
    b"color:var(--green);font-weight:700;margin-bottom:12px}"
    b"a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}"
    b"footer{text-align:center;padding:10px 0 24px}"
    b".footer-inner{display:inline-flex;align-items:center;gap:10px;"
    b"background:linear-gradient(135deg,#030810,#050f20);border:1px solid #0a2040;"
    b"border-radius:99px;padding:6px 16px;opacity:.35;transition:opacity .3s}"
    b".footer-inner:hover{opacity:.85}"
    b".footer-by{font-size:.68rem;color:#3a6090;display:flex;align-items:center;gap:6px}"
    b".footer-by a{font-weight:600;background:linear-gradient(90deg,#1a5a99,#0a8a6a);"
    b"-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-decoration:none}"
    b".footer-sep{width:1px;height:12px;background:#0d2a50}"
    b".footer-claude{font-size:.65rem;color:#2a4a6a}"
    b".claude-badge{font-size:.62rem;font-weight:600;background:linear-gradient(135deg,#041828,#051f3a);"
    b"border:1px solid #0d3060;border-radius:4px;padding:1px 7px;color:#1a5a88}"
    b"</style></head><body>"
    b"<header>"
    b"  <div class='logo-wrap'>"
    b"    <div class='logo'>&#x1F6E1;&#xFE0F;</div>"
    b"    <div><h1>Match IP API</h1><span>Documenta&ccedil;&atilde;o dos Endpoints</span></div>"
    b"  </div>"
    b"  <div class='header-links'>"
    b"    <a href='/' class='hl hl-outline'>&#x1F310; Site</a>"
    b"    <a href='https://github.com/FlowTemperature' target='_blank' class='hl hl-outline'>GitHub</a>"
    b"    <a href='https://www.npmjs.com/package/@flowtemperature/matchip' target='_blank' class='hl hl-fill'>&#x1F4E6; npm</a>"
    b"  </div>"
    b"</header>"
    b"<div class='wrap'>"
    b"  <div class='hero'>"
    b"    <h2>API Reference</h2>"
    b"    <p>API p&uacute;blica e gratuita para verifica&ccedil;&atilde;o e an&aacute;lise de IPs. Sem autentica&ccedil;&atilde;o necess&aacute;ria.</p>"
    b"    <div class='base-url'>"
    b"      <span id='base-url'>https://matchip.squareweb.app</span>"
    b"      <button class='copy-btn' onclick=\"navigator.clipboard.writeText(document.getElementById('base-url').textContent);this.textContent='Copiado!';setTimeout(()=>this.textContent='Copiar',2000)\">Copiar</button>"
    b"    </div>"
    b"  </div>"
    b"  <div class='section-title'>Endpoints</div>"
    b"  <div class='endpoint'>"
    b"    <div class='ep-header'><span class='method get'>GET</span><span class='ep-path'>/ping</span><span class='ep-desc'>Health check</span></div>"
    b"    <div class='ep-body'><p>Verifica se a API est&aacute; online.</p>"
    b"    <div class='lbl2'>Resposta</div>"
    b"    <pre>{ <span class='key'>\"status\"</span>: <span class='str'>\"ok\"</span>, <span class='key'>\"version\"</span>: <span class='str'>\"1.0.0\"</span> }</pre>"
    b"    <div class='lbl2'>Exemplo</div>"
    b"    <pre><span class='kw'>curl</span> https://matchip.squareweb.app/ping</pre></div>"
    b"  </div>"
    b"  <div class='endpoint'>"
    b"    <div class='ep-header'><span class='method get'>GET</span><span class='ep-path'>/api/check/:ip</span><span class='ep-desc'>Verificar IP no AbuseIPDB</span></div>"
    b"    <div class='ep-body'><p>Retorna dados completos do IP diretamente do AbuseIPDB.</p>"
    b"    <div class='lbl2'>Exemplo</div>"
    b"    <pre><span class='kw'>curl</span> https://matchip.squareweb.app/api/check/8.8.8.8</pre></div>"
    b"  </div>"
    b"  <div class='endpoint'>"
    b"    <div class='ep-header'><span class='method post'>POST</span><span class='ep-path'>/analyze</span><span class='ep-desc'>IP + An&aacute;lise de IA (CLI)</span></div>"
    b"    <div class='ep-body'><p>Combina AbuseIPDB com an&aacute;lise gerada por Llama 3.1. Usado pela CLI matchip.</p>"
    b"    <div class='lbl2'>Body</div>"
    b"    <pre>{ <span class='key'>\"ip\"</span>: <span class='str'>\"185.220.101.1\"</span> }</pre>"
    b"    <div class='lbl2'>Exemplo</div>"
    b"    <pre><span class='kw'>curl</span> -X POST https://matchip.squareweb.app/analyze \\\n"
    b"  -H <span class='str'>\"Content-Type: application/json\"</span> \\\n"
    b"  -d <span class='str'>'{\"ip\": \"185.220.101.1\"}'</span></pre></div>"
    b"  </div>"
    b"  <div class='divider'></div>"
    b"  <div class='section-title'>CLI &mdash; Match IP</div>"
    b"  <div class='cli-box'>"
    b"    <div class='cli-title'>&#x1F4E6; Instala&ccedil;&atilde;o</div>"
    b"    <pre><span class='kw'>npm</span> install -g @flowtemperature/matchip\n<span class='kw'>npx</span> @flowtemperature/matchip 8.8.8.8</pre>"
    b"  </div>"
    b"  <div class='cli-box'>"
    b"    <div class='cli-title'>&#x1F4BB; Uso</div>"
    b"    <pre><span class='kw'>matchip</span> <span class='str'>8.8.8.8</span>   <span class='key'># analisa IP</span>\n<span class='kw'>matchip</span> <span class='str'>ping</span>      <span class='key'># verifica API</span>\n<span class='kw'>matchip</span> <span class='str'>help</span>      <span class='key'># ajuda</span></pre>"
    b"  </div>"
    b"  <div class='divider'></div>"
    b"  <div class='section-title'>Limites &amp; Notas</div>"
    b"  <div style='background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:22px;font-size:.88rem;line-height:1.8;color:var(--text2)'>"
    b"    <p>&#x2022; API <strong style='color:var(--text)'>gratuita e p&uacute;blica</strong> &mdash; sem autentica&ccedil;&atilde;o.</p>"
    b"    <p>&#x2022; Dados fornecidos pelo <a href='https://www.abuseipdb.com' target='_blank'>AbuseIPDB</a>.</p>"
    b"    <p>&#x2022; An&aacute;lise de IA gerada pelo <strong style='color:var(--text)'>Llama 3.1 8B</strong> via Flow API.</p>"
    b"    <p>&#x2022; IPs com score &ge; 25 s&atilde;o <strong style='color:var(--red)'>bloqueados automaticamente</strong>.</p>"
    b"    <p>&#x2022; Rate limit: 30 requisi&ccedil;&otilde;es / 60 segundos por IP.</p>"
    b"    <p>&#x2022; Licen&ccedil;a: <a href='https://github.com/FlowTemperature' target='_blank'>MIT</a></p>"
    b"  </div>"
    b"</div>"
    b"<footer><div class='footer-inner'>"
    b"  <div class='footer-by'>Criado por <a href='https://github.com/FlowTemperature' target='_blank'>FlowTemperature</a></div>"
    b"  <div class='footer-sep'></div>"
    b"  <div class='footer-claude'>com ajuda de <span class='claude-badge'>Claude</span></div>"
    b"</div></footer>"
    b"</body></html>"
)

print("✅ HTML OK")

# ─── Handler ──────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def get_client_ip(self):
        return (
            self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or self.headers.get("X-Real-IP", "")
            or self.client_address[0]
        )

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type",                "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length",              len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body_bytes, status=200):
        self.send_response(status)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body_bytes))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        ip = self.get_client_ip()

        # Verifica visitante apenas em rotas HTML (não na API nem no /ping)
        if not self.path.startswith("/api/") and self.path != "/ping":
            blocked, reason = check_visitor(ip)
            if blocked:
                self.send_html(page_blocked(), 403)
                return

        # Rate limit em todas as rotas
        if not rate_check(ip):
            self.send_html(page_ratelimit(), 429)
            return

        if self.path in ("/", "/index.html"):
            self.send_html(HTML)
            return

        if self.path == "/docs":
            self.send_html(DOCS_HTML)
            return

        if self.path == "/ping":
            self.send_json({"status": "ok", "version": "1.0.0"})
            return

        if self.path.startswith("/api/check/"):
            target_ip = urllib.parse.unquote(self.path[len("/api/check/"):])
            data, status = do_abuse_check(target_ip, verbose=True)
            self.send_json(data, status)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        ip = self.get_client_ip()

        if not rate_check(ip):
            self.send_json({"error": "rate limit"}, 429)
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self.send_json({"error": "JSON invalido"}, 400)
            return

        # /api/flow — usado pelo site
        if self.path == "/api/flow":
            msg   = body.get("message", "")
            reply = do_flow(msg)
            self.send_json({"reply": reply or "IA nao disponivel."})
            return

        # /analyze — usado pela CLI matchip
        if self.path == "/analyze":
            target_ip = body.get("ip", "").strip()
            if not target_ip:
                self.send_json({"error": "IP obrigatorio"}, 400)
                return

            abuse_data, _ = do_abuse_check(target_ip, verbose=True)
            d     = abuse_data.get("data", {})
            score = d.get("abuseConfidenceScore", 0)

            prompt = (
                f"Você é um analista sênior de threat intelligence com 15 anos de experiência. "
                f"Analise o IP abaixo com raciocínio técnico real.\n\n"
                f"DADOS DO IP: {target_ip}\n"
                f"Score AbuseIPDB: {score}/100\n"
                f"País: {d.get('countryCode')} | ISP: {d.get('isp')} | Domínio: {d.get('domain','N/A')}\n"
                f"Tipo de uso: {d.get('usageType','desconhecido')} | Reportes: {d.get('totalReports')} | Tor: {d.get('isTor')}\n\n"
                f"REGRAS:\n"
                f"- Score 0-10 com ISP conhecido (Google, Cloudflare, AWS): provavelmente legítimo\n"
                f"- Score 50+: indício real de ameaça\n"
                f"- Score 75+: ameaça confirmada, recomende bloqueio imediato\n"
                f"- IPs de DNS públicos (8.8.8.8, 1.1.1.1): infraestrutura legítima\n\n"
                f"Responda EXATAMENTE neste formato:\n"
                f"NÍVEL: <Crítico|Alto|Médio|Baixo|Seguro>\n"
                f"PERFIL: <1 linha>\n"
                f"AÇÃO: <bloquear|monitorar|ignorar> — <motivo em 1 linha>"
            )
            ai_reply = do_flow(prompt) or "IA nao disponivel."

            self.send_json({
                "ip":             target_ip,
                "score":          score,
                "country":        d.get("countryCode"),
                "isp":            d.get("isp"),
                "reports":        d.get("totalReports"),
                "isTor":          d.get("isTor"),
                "domain":         d.get("domain"),
                "lastReportedAt": d.get("lastReportedAt"),
                "ai":             ai_reply,
            })
            return

        self.send_response(404)
        self.end_headers()

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        port = int(os.getenv("PORT", 80))
        print(f"✅ Match IP rodando na porta {port}")
        print(f"   Site          : GET  /")
        print(f"   Docs          : GET  /docs")
        print(f"   CLI ping      : GET  /ping")
        print(f"   CLI analyze   : POST /analyze")
        print(f"   AbuseIPDB keys: {len(abuse_keys)}")
        print(f"   Flow keys     : {len(flow_keys)}")
        print(f"   Block score   : >= {BLOCK_SCORE}")
        print(f"   Rate limit    : {RATE_MAX_REQ} req / {RATE_WINDOW}s")
        HTTPServer(("0.0.0.0", port), Handler).serve_forever()
    except Exception as e:
        print(f"❌ ERRO AO INICIAR SERVIDOR: {e}")
        traceback.print_exc()
        sys.exit(1)
