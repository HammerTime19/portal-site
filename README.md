# Web Honeypot & Threat Dashboard

A web honeypot that poses as the employee portal of a made-up logistics company,
"Northbridge Freight". It records what real attackers on the internet try against it,
then sorts and maps that activity on a password-protected dashboard.

Built with Python, Flask and PostgreSQL, and deployed on Render.

## What attackers see

- An employee portal home page with a sign-in link and a document-upload link
- Fake login pages at `/login`, `/admin`, `/admin/login` and `/phpmyadmin/`
- A fake WordPress login page at `/wp-login.php` and `/wp-admin/`
- A "shipping documents" upload form at `/upload`
- A bait `/.env` file and a `robots.txt` that points at "hidden" paths
- Apache/PHP server headers, so the site looks like a typical LAMP server

Every login fails and every upload "fails", so attackers keep trying different things.

> **The credentials in `/.env` are fake.** The database password and AWS keys in
> `FAKE_ENV` (in `app.py`) are made-up bait values. They don't work anywhere.

## What gets recorded

Every request is stored in PostgreSQL with:

- Source IP (taken from `X-Forwarded-For`), method, path, query string and user-agent
- Request body (first 4 KB)
- Usernames and passwords submitted to any login form, matched across common
  field names (`username`, `log`, `pwd`, `pma_password` and others)
- Uploaded files as **metadata only**: file name, size, SHA-256 hash and the first
  bytes, used to identify the file type. The file contents are never saved.

Events go onto an in-memory queue and a background thread writes them to the
database in batches. That way the bait pages respond instantly even if the
database is slow or briefly down. Database connections are opened inside each
Gunicorn worker process, not at startup, so the app works with several workers.

## How traffic is analysed

**Attack type.** Each request is matched against regex patterns for:

- Log4Shell / JNDI injection
- Command injection
- SQL injection
- Path traversal
- Cross-site scripting
- Secret / config file hunting (`.env`, `.git/`, `wp-config`, backups)
- Known-exploit probing (phpunit, ThinkPHP, `/cgi-bin/`, Spring actuator and others)
- Admin panel / CMS probing

Anything that matches none of these is labelled as recon / crawling.

**Tool.** The user-agent is matched against known scanners and clients: sqlmap,
Nikto, Nuclei, ZGrab, masscan, Nmap, Gobuster, ffuf, WPScan, Censys, Shodan, Palo Alto
Expanse, and generic Python, Go, curl and wget clients.

**File type.** Uploaded files are identified from their first bytes, for example Linux
ELF or Windows executables, ZIP/Office files, PDFs, PHP and shell scripts, and gzip archives.

**Location.** IP addresses are looked up through the ip-api.com batch API. Results
are cached in a `geo` table so each IP is only looked up once.

## Dashboard

The dashboard is at `/hp-dashboard` and uses HTTP Basic auth with `DASHBOARD_PASSWORD`.
It shows:

- Totals for attacker IPs, requests, login attempts, uploads and countries
- A world map of attacker locations (Leaflet)
- A breakdown of attack types and the top countries
- A per-IP table with location, ISP, request and login counts, main attack type,
  tools used and when the IP was last seen. Click an IP to see only its activity.
- The most common usernames, passwords and probed paths
- Uploaded files, each with a VirusTotal link for its hash
- A live feed of the latest activity
- A view of the last 1, 7 or 30 days, and a CSV export of that period

## Running it

### On Render

`render.yaml` is a Render Blueprint. It creates a free PostgreSQL database and a
web service that runs Gunicorn (2 workers, 4 threads each). `DATABASE_URL` is filled
in automatically. Set `DASHBOARD_PASSWORD` yourself in the Render dashboard.

### Locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://user:pass@localhost:5432/honeypot   # optional
export DASHBOARD_PASSWORD=choose-a-password
flask --app app run
```

Without `DATABASE_URL`, events are printed to the console as JSON and the dashboard
is turned off.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `DASHBOARD_PASSWORD` | Password for `/hp-dashboard` (any username works) |

## Design notes

- **Safe by design.** The honeypot only serves static bait pages. It never runs
  submitted input, never saves uploaded file contents, and never connects back
  to an attacker.
- **Real data, not lab data.** It runs on a public URL and only records requests that
  come in through Render's proxy, so Render's own health checks and internal
  traffic are left out.
- **No secrets in the repo.** All real credentials come from environment variables.

## Tech stack

Python 3.12 · Flask · Gunicorn · PostgreSQL (psycopg 3) · Leaflet · Render
