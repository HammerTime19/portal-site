"""Web honeypot with a built-in dashboard.

Attackers see: a fake company portal, fake login pages, bait files and an upload form.
You see: /hp-dashboard (password protected) with IPs, locations, a world map,
credentials tried, files uploaded and how each attacker tried to get in.

Env:  DATABASE_URL        Postgres connection string (Render fills this in)
      DASHBOARD_PASSWORD  password for /hp-dashboard (any username)
"""
import csv
import hashlib
import io
import json
import os
import re
import secrets
import sys
from collections import Counter

import requests as http
from flask import Flask, Response, render_template_string, request

DATABASE_URL = os.environ.get("DATABASE_URL")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
DASH = "/hp-dashboard"
COMPANY = "Northbridge Freight"
MAX_BODY = 4096

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(), event_type TEXT NOT NULL,
    src_ip TEXT, xff_raw TEXT, method TEXT, path TEXT, query TEXT, status INT, user_agent TEXT,
    body TEXT, username TEXT, password TEXT, file_name TEXT, file_size BIGINT, file_sha256 TEXT, file_magic TEXT);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts);
CREATE TABLE IF NOT EXISTS geo (ip TEXT PRIMARY KEY, data JSONB NOT NULL);
"""
COLUMNS = ["event_type", "src_ip", "xff_raw", "method", "path", "query", "status", "user_agent", "body",
           "username", "password", "file_name", "file_size", "file_sha256", "file_magic"]
INSERT = f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join(['%s'] * len(COLUMNS))})"

pool = None
if DATABASE_URL:
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool
    pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=4, open=True,
                          kwargs={"prepare_threshold": None, "connect_timeout": 10})

_schema_ready = False


def ensure_schema():
    """Create tables if missing. Retried on every use until it succeeds, so a database
    that wasn't ready when the site started doesn't break anything."""
    global _schema_ready
    if _schema_ready or pool is None:
        return
    with pool.connection() as conn:
        conn.execute(SCHEMA)
    _schema_ready = True


# =====================================================================
# Recording every request
# =====================================================================

USER_FIELDS = ("username", "user", "log", "login", "email", "uname", "user_login", "pma_username")
PASS_FIELDS = ("password", "pass", "pwd", "passwd", "user_pass", "pma_password")


def save(rows):
    if pool is None:
        for r in rows:
            print(json.dumps(r, default=str), flush=True)
        return
    try:
        ensure_schema()
        with pool.connection() as conn:
            conn.cursor().executemany(INSERT, [[r.get(c) for c in COLUMNS] for r in rows])
    except Exception as e:  # a database hiccup must never break the bait
        print(f"db write failed: {e}", file=sys.stderr)


@app.after_request
def record(response):
    if request.path.startswith(DASH) or request.path in ("/healthz", "/favicon.ico"):
        return response
    xff = request.headers.get("X-Forwarded-For", "")
    status = response.status_code
    base = {"src_ip": xff.split(",")[0].strip() if xff else request.remote_addr, "xff_raw": xff or None,
            "method": request.method, "path": request.path,
            "query": request.query_string.decode(errors="replace")[:MAX_BODY] or None,
            "user_agent": request.headers.get("User-Agent")}

    body = None
    if request.method not in ("GET", "HEAD") and request.mimetype != "multipart/form-data":
        try:
            body = request.get_data(cache=True)[:MAX_BODY].decode(errors="replace") or None
        except Exception:
            body, status = "[body larger than 10 MB, not read]", 413
    rows = [{**base, "status": status, "event_type": "request", "body": body}]

    form, files = {}, []
    if request.method == "POST" and status != 413:
        try:
            form, files = request.form, list(request.files.items(multi=True))
        except Exception:
            pass
    username = next((form[f] for f in USER_FIELDS if form.get(f)), None)
    password = next((form[f] for f in PASS_FIELDS if form.get(f)), None)
    if username or password:
        rows.append({**base, "status": status, "event_type": "login", "username": username, "password": password})

    for _, f in files:  # hash the file, keep nothing else
        sha, size, magic = hashlib.sha256(), 0, b""
        for chunk in iter(lambda: f.stream.read(65536), b""):
            magic = magic or chunk[:16]
            sha.update(chunk)
            size += len(chunk)
        rows.append({**base, "status": status, "event_type": "upload", "file_name": f.filename,
                     "file_size": size, "file_sha256": sha.hexdigest(), "file_magic": magic.hex()})

    save(rows)
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    return response


# =====================================================================
# Bait pages (what attackers see)
# =====================================================================

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{{ title }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{font-family:Segoe UI,Arial,sans-serif;background:#eef1f4;margin:0;color:#1f2a36}
header{background:#1d3b5a;color:#fff;padding:14px 24px;font-size:18px}
main{max-width:380px;margin:60px auto;background:#fff;padding:28px;border:1px solid #d5dbe1;border-radius:4px}
label{display:block;font-size:14px;margin:12px 0 4px}input{width:100%;padding:8px;box-sizing:border-box;border:1px solid #b8c2cc}
button{margin-top:18px;width:100%;padding:10px;background:#1d3b5a;color:#fff;border:0}
.err{color:#b3261e;font-size:14px}footer{text-align:center;font-size:12px;color:#6b7785;margin-top:20px}
</style></head><body><header>{{ company }}</header><main>{{ content|safe }}</main>
<footer>&copy; 2026 {{ company }}. Authorized users only.</footer></body></html>"""

LOGIN = """<h2>{{ heading }}</h2>{% if error %}<p class="err">Invalid username or password.</p>{% endif %}
<form method="post"><label>Username</label><input name="username">
<label>Password</label><input name="password" type="password"><button>Sign in</button></form>"""

WP_LOGIN = """<!doctype html><html><head><title>Log In &lsaquo; {{ company }} &#8212; WordPress</title><style>
body{background:#f0f0f1;font-family:Segoe UI,Roboto,sans-serif}#login{width:320px;margin:8% auto}
form{background:#fff;padding:26px 24px;border:1px solid #c3c4c7}input{width:100%;padding:6px;margin:4px 0 14px;box-sizing:border-box}
.err{background:#fff;border-left:4px solid #d63638;padding:12px;margin-bottom:16px}</style></head><body><div id="login">
{% if error %}<div class="err"><strong>Error:</strong> The password you entered for the username is incorrect.</div>{% endif %}
<form method="post" action="/wp-login.php"><label>Username or Email Address</label><input name="log">
<label>Password</label><input name="pwd" type="password"><input type="submit" value="Log In"></form></div></body></html>"""

UPLOAD = """<h2>Upload shipping documents</h2>{% if done %}<p class="err">Upload failed: file could not be processed.</p>{% endif %}
<form method="post" enctype="multipart/form-data"><label>Document</label><input type="file" name="file"><button>Upload</button></form>"""

FAKE_ENV = """APP_ENV=production
DB_HOST=10.0.12.8
DB_DATABASE=nbf_portal
DB_USERNAME=portal_app
DB_PASSWORD=Nbf!Portal2025
AWS_ACCESS_KEY_ID=AKIA4NBFEXAMPLE7QX2
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


def page(title, content, **ctx):
    return render_template_string(PAGE, title=title, company=COMPANY, content=render_template_string(content, **ctx))


@app.route("/")
def index():
    return page(f"{COMPANY} | Employee Portal", '<h2>Employee Portal</h2><p>Sign in to access dispatch, invoicing '
                'and HR tools.</p><p><a href="/login">Sign in</a> &middot; <a href="/upload">Upload documents</a></p>')


@app.route("/login", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/login", methods=["GET", "POST"])
@app.route("/phpmyadmin/", methods=["GET", "POST"])
def login():
    return page(f"Sign in | {COMPANY}", LOGIN, heading="Sign in", error=request.method == "POST")


@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
def wp_login():
    return render_template_string(WP_LOGIN, company=COMPANY, error=request.method == "POST")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    return page(f"Upload | {COMPANY}", UPLOAD, done=request.method == "POST")


@app.route("/.env")
def env():
    return Response(FAKE_ENV, mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /upload\nDisallow: /backup/\n", mimetype="text/plain")


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/<path:anything>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def not_found(anything):
    return page("404 Not Found", "<h2>Not Found</h2><p>The requested URL was not found on this server.</p>"), 404


@app.errorhandler(405)
def not_allowed(_):
    return page("405", "<h2>Method Not Allowed</h2>"), 405


# =====================================================================
# Analysis helpers
# =====================================================================

ATTACKS = [(name, re.compile(p, re.I)) for name, p in [
    ("Log4Shell / JNDI injection", r"\$\{jndi:|\$\{\$\{"),
    ("Command injection", r"(;|\||&&|`|\$\()\s*(wget|curl|sh|bash|busybox|nc|chmod|cd\s)|/bin/(ba)?sh|shell_exec|"
                          r"cmd=|exec=|eval-stdin|allow_url_include"),
    ("SQL injection", r"union(\s|\+|%20)+(all(\s|\+|%20)+)?select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d|"
                      r"information_schema|benchmark\(|waitfor(\s|%20)+delay"),
    ("Path traversal", r"\.\./|\.\.%2f|%2e%2e|/etc/passwd|win\.ini|/proc/self"),
    ("Cross-site scripting", r"<script|%3cscript|onerror=|javascript:"),
    ("Secret / config file hunting", r"\.env|\.git/|\.aws/|\.ssh/|wp-config|config\.(php|json|ya?ml|js)|\.sql$|"
                                     r"backup|\.bak|docker-compose|credentials"),
    ("Known-exploit probing", r"phpunit|thinkphp|/cgi-bin/|boaform|/HNAP1|actuator|solr|struts|\.cgi|/owa/|"
                              r"autodiscover|vendor/|shell\.php|/geoserver"),
    ("Admin panel / CMS probing", r"wp-(login|admin|content|includes)|xmlrpc|phpmyadmin|/admin|/login|"
                                  r"/manager/html|/administrator"),
]]
TOOLS = [("sqlmap", "sqlmap"), ("nikto", "Nikto"), ("nuclei", "Nuclei"), ("zgrab", "ZGrab"), ("masscan", "masscan"),
         ("nmap", "Nmap"), ("gobuster", "Gobuster"), ("ffuf", "ffuf"), ("wpscan", "WPScan"), ("censys", "Censys"),
         ("shodan", "Shodan"), ("expanse", "Palo Alto Expanse"), ("python-requests", "Python script"),
         ("aiohttp", "Python script"), ("go-http-client", "Go program"), ("curl", "curl"), ("wget", "wget"),
         ("libwww-perl", "Perl script"), ("bot", "Crawler / bot"), ("mozilla", "Browser-like")]
MAGIC = {"7f454c46": "Linux executable (ELF)", "4d5a": "Windows executable", "504b0304": "ZIP / Office",
         "25504446": "PDF", "2321": "Script", "3c3f706870": "PHP script", "1f8b": "gzip archive"}


def attack_type(e):
    if e["event_type"] == "login":
        return "Credential attempt"
    if e["event_type"] == "upload":
        return "File upload"
    text = " ".join(filter(None, [e["path"], e["query"], e["body"]]))
    return next((name for name, rx in ATTACKS if rx.search(text)), "Recon / crawling")


def tool_of(ua):
    if not ua or not ua.strip():
        return "No user-agent"
    return next((label for key, label in TOOLS if key in ua.lower()), "Other")


def file_kind(magic):
    return next((label for sig, label in MAGIC.items() if (magic or "").startswith(sig)), "Other / text")


def locate(ips):
    """Country/city/ISP for each IP via ip-api.com, saved so each IP is looked up once."""
    with pool.connection() as conn:
        found = {r[0]: r[1] for r in conn.execute("SELECT ip, data FROM geo WHERE ip = ANY(%s)", (list(ips),))}
    missing = [ip for ip in ips if ip not in found][:300]  # at most 3 lookups per page load
    for i in range(0, len(missing), 100):
        try:
            r = http.post("http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp,as",
                          json=missing[i:i + 100], timeout=10)
            new = {x["query"]: (x if x.get("status") == "success" else {"country": "Unknown"}) for x in r.json()}
        except Exception as e:
            print(f"geo lookup failed: {e}", file=sys.stderr)
            break
        with pool.connection() as conn:
            conn.cursor().executemany("INSERT INTO geo VALUES (%s, %s) ON CONFLICT DO NOTHING",
                                      [(ip, json.dumps(d)) for ip, d in new.items()])
        found.update(new)
    return found


def load(days, ip=None):
    sql = "SELECT * FROM events WHERE ts >= now() - make_interval(days => %s)"
    args = [days]
    if ip:
        sql += " AND src_ip = %s"
        args.append(ip)
    with pool.connection() as conn:
        rows = conn.cursor(row_factory=dict_row).execute(sql + " ORDER BY ts DESC LIMIT 50000", args).fetchall()
    for e in rows:
        e["attack"] = attack_type(e)
        e["tool"] = tool_of(e["user_agent"])
    return rows


# =====================================================================
# Dashboard (what you see)
# =====================================================================

def authorized():
    auth = request.authorization
    return bool(DASHBOARD_PASSWORD and auth and secrets.compare_digest(auth.password or "", DASHBOARD_PASSWORD))


def ask_password():
    return Response("Password required", 401, {"WWW-Authenticate": 'Basic realm="Restricted"'})


DASH_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Honeypot dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#15202b;color:#e6edf3}
.wrap{max-width:1200px;margin:0 auto;padding:20px}h1{margin:0 0 4px;font-size:24px}h2{font-size:18px;margin:28px 0 10px}
a{color:#e8a33d}.sub{color:#9fb0c0;font-size:14px}
.nums{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.num{background:#1e2b38;padding:14px;border-radius:6px}.num b{display:block;font-size:26px;color:#e8a33d}
.num span{font-size:13px;color:#9fb0c0}#map{height:440px;border-radius:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px}
table{width:100%;border-collapse:collapse;font-size:13px;background:#1e2b38;border-radius:6px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #2c3b4a;vertical-align:top}th{color:#9fb0c0;font-weight:600}
td.w{word-break:break-all}.scroll{max-height:420px;overflow:auto;border-radius:6px}
.bar{background:#e8a33d;height:10px;border-radius:2px}
</style></head><body><div class="wrap">
<h1>Honeypot dashboard</h1>
<div class="sub">Last {{ days }} days{% if ip %} &middot; IP {{ ip }} &middot; <a href="?days={{ days }}">back to all</a>{% endif %}
&middot; <a href="?days=1">1 day</a> <a href="?days=7">7 days</a> <a href="?days=30">30 days</a>
&middot; <a href="{{ dash }}/export.csv?days={{ days }}">Download CSV</a></div>

<div class="nums">
<div class="num"><b>{{ ips|length }}</b><span>Attacker IPs</span></div>
<div class="num"><b>{{ n_requests }}</b><span>Requests</span></div>
<div class="num"><b>{{ logins|length }}</b><span>Login attempts</span></div>
<div class="num"><b>{{ uploads|length }}</b><span>Files uploaded</span></div>
<div class="num"><b>{{ countries|length }}</b><span>Countries</span></div></div>

<h2>Where attacks come from</h2><div id="map"></div>

<div class="grid">
<div><h2>How they tried to get in</h2><table>{% for name, n in attacks %}<tr><td>{{ name }}</td><td>{{ n }}</td>
<td style="width:40%"><div class="bar" style="width:{{ (100 * n / attacks[0][1])|round|int }}%"></div></td></tr>{% endfor %}</table></div>
<div><h2>Top countries</h2><table><tr><th>Country</th><th>IPs</th></tr>
{% for c, n in countries[:12] %}<tr><td>{{ c }}</td><td>{{ n }}</td></tr>{% endfor %}</table></div>
</div>

<h2>Attacker IPs</h2><div class="scroll"><table><tr><th>IP</th><th>Location</th><th>ISP</th><th>Requests</th>
<th>Logins</th><th>Uploads</th><th>Main attack</th><th>Tools</th><th>Last seen (UTC)</th></tr>
{% for a in ips %}<tr><td><a href="?days={{ days }}&ip={{ a.ip }}">{{ a.ip }}</a></td><td>{{ a.city }}{{ ', ' if a.city }}{{ a.country }}</td>
<td>{{ a.isp }}</td><td>{{ a.requests }}</td><td>{{ a.logins }}</td><td>{{ a.uploads }}</td><td>{{ a.main }}</td>
<td>{{ a.tools }}</td><td>{{ a.last }}</td></tr>{% endfor %}</table></div>

<div class="grid">
<div><h2>Top usernames</h2><table>{% for u, n in users %}<tr><td class="w">{{ u }}</td><td>{{ n }}</td></tr>{% else %}<tr><td>None yet</td></tr>{% endfor %}</table></div>
<div><h2>Top passwords</h2><table>{% for p, n in passwords %}<tr><td class="w">{{ p }}</td><td>{{ n }}</td></tr>{% else %}<tr><td>None yet</td></tr>{% endfor %}</table></div>
<div><h2>Most-probed paths</h2><table>{% for p, n in paths %}<tr><td class="w">{{ p }}</td><td>{{ n }}</td></tr>{% endfor %}</table></div>
</div>

<h2>Files uploaded</h2>{% if uploads %}<div class="scroll"><table><tr><th>Time (UTC)</th><th>IP</th><th>File name</th><th>Type</th>
<th>Size</th><th>SHA-256</th></tr>{% for f in uploads %}<tr><td>{{ f.ts }}</td><td>{{ f.src_ip }}</td><td class="w">{{ f.file_name }}</td>
<td>{{ f.kind }}</td><td>{{ f.file_size }}</td><td class="w"><a href="https://www.virustotal.com/gui/file/{{ f.file_sha256 }}"
target="_blank" rel="noopener">{{ f.file_sha256 }}</a></td></tr>{% endfor %}</table></div>
{% else %}<p class="sub">No uploads yet.</p>{% endif %}

<h2>Latest activity</h2><div class="scroll"><table><tr><th>Time (UTC)</th><th>IP</th><th>Type</th><th>Request</th>
<th>Username / password</th><th>Tool</th></tr>{% for e in recent %}<tr><td>{{ e.ts }}</td><td>{{ e.src_ip }}</td><td>{{ e.attack }}</td>
<td class="w">{{ e.method }} {{ e.path }}{{ '?' ~ e.query if e.query }}{{ ' ' ~ e.body[:200] if e.body }}</td>
<td class="w">{{ e.username or '' }}{{ ' / ' ~ e.password if e.password }}</td><td>{{ e.tool }}</td></tr>{% endfor %}</table></div>
</div>
<script>
const points = {{ points|tojson }};
const map = L.map('map', {worldCopyJump: true}).setView([25, 10], 2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  {attribution: '&copy; OpenStreetMap &copy; CARTO', maxZoom: 10}).addTo(map);
points.forEach(p => L.circleMarker([p.lat, p.lon], {radius: Math.min(4 + Math.sqrt(p.requests) * 2, 22),
  color: '#e8a33d', fillColor: '#e8a33d', fillOpacity: 0.5, weight: 1})
  .bindPopup(`<b>${p.ip}</b><br>${p.city || ''} ${p.country}<br>${p.isp || ''}<br>${p.requests} requests, ${p.logins} logins<br>${p.main}`)
  .addTo(map));
</script></body></html>"""


@app.route(DASH)
def dashboard():
    if not authorized():
        return ask_password()
    if pool is None:
        return "DATABASE_URL is not set, so there is nothing to show yet."
    try:
        ensure_schema()
        return build_dashboard()
    except Exception:
        import traceback
        return Response("Dashboard error. Send this to Claude:\n\n" + traceback.format_exc(), 500,
                        mimetype="text/plain")


def build_dashboard():
    days = max(1, min(int(request.args.get("days", 7) or 7), 365))
    ip_filter = request.args.get("ip") or None
    events = load(days, ip_filter)

    per_ip = {}
    for e in events:
        a = per_ip.setdefault(e["src_ip"], {"ip": e["src_ip"], "requests": 0, "logins": 0, "uploads": 0,
                                            "attacks": Counter(), "tools": set(), "last": e["ts"]})
        if e["event_type"] == "request":
            a["requests"] += 1
            a["attacks"][e["attack"]] += 1
        a["logins"] += e["event_type"] == "login"
        a["uploads"] += e["event_type"] == "upload"
        a["tools"].add(e["tool"])
    geo = locate(list(per_ip))
    for a in per_ip.values():
        g = geo.get(a["ip"], {})
        a.update(country=g.get("country") or "Unknown", city=g.get("city"), isp=g.get("isp"),
                 lat=g.get("lat"), lon=g.get("lon"), main=(a["attacks"].most_common(1) or [("-", 0)])[0][0],
                 tools=", ".join(sorted(a["tools"])), last=a["last"].strftime("%Y-%m-%d %H:%M"))
    ips = sorted(per_ip.values(), key=lambda a: -a["requests"])
    logins = [e for e in events if e["event_type"] == "login"]
    uploads = [dict(e, kind=file_kind(e["file_magic"]), ts=e["ts"].strftime("%Y-%m-%d %H:%M"))
               for e in events if e["event_type"] == "upload"]
    reqs = [e for e in events if e["event_type"] == "request"]
    # A login or upload also creates a plain "request" row with the same timestamp; count each action once
    paired = {(e["src_ip"], e["ts"]) for e in events if e["event_type"] != "request"}
    actions = [e for e in events if e["event_type"] != "request" or (e["src_ip"], e["ts"]) not in paired]
    recent = [dict(e, ts=e["ts"].strftime("%Y-%m-%d %H:%M:%S")) for e in actions[:150]]

    return render_template_string(
        DASH_HTML, dash=DASH, days=days, ip=ip_filter, ips=ips, n_requests=len(reqs), logins=logins, uploads=uploads,
        countries=Counter(a["country"] for a in ips if a["country"] != "Unknown").most_common(),
        attacks=Counter(e["attack"] for e in actions).most_common() or [("None yet", 1)],
        users=Counter(e["username"] for e in logins if e["username"]).most_common(15),
        passwords=Counter(e["password"] for e in logins if e["password"]).most_common(15),
        paths=Counter(e["path"] for e in reqs).most_common(15), recent=recent,
        points=[{k: a[k] for k in ("ip", "lat", "lon", "country", "city", "isp", "requests", "logins", "main")}
                for a in ips if a["lat"] is not None])


@app.route(DASH + "/export.csv")
def export():
    if not authorized():
        return ask_password()
    ensure_schema()
    days = max(1, min(int(request.args.get("days", 30) or 30), 365))
    events = load(days)
    geo = locate(list({e["src_ip"] for e in events}))
    out = io.StringIO()
    fields = ["ts", "src_ip", "country", "city", "isp", "event_type", "attack", "tool", "method", "path", "query",
              "status", "username", "password", "file_name", "file_size", "file_sha256", "user_agent", "body"]
    w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for e in events:
        g = geo.get(e["src_ip"], {})
        w.writerow({**e, "country": g.get("country"), "city": g.get("city"), "isp": g.get("isp")})
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=honeypot_{days}d.csv"})
