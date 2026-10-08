# Web Honeypot & Threat Dashboard

A web honeypot that poses as the employee portal of a made-up logistics company,
"Northbridge Freight". It records what real attackers on the internet try against it,
then sorts and maps that activity on a password-protected dashboard.

Built with Python, Flask and PostgreSQL, deployed on Render behind a custom domain
managed in Cloudflare.

![Dashboard overview: totals and a world map of attacker locations](docs/dashboard-overview.png)

## Results (first 15 days)

Live on the public internet from 23 September to 8 October 2026:

- **10,700+ requests from 1,300+ IP addresses in 61 countries.** The most IPs came
  from the United States, Kazakhstan, Singapore, Germany and Japan, mostly cloud and
  hosting providers.
- **Scanners found it fast.** The first request for the bait `/.env` file came about an
  hour after the first visit. Over the 15 days, 38 IPs requested `/.env`, along with
  variants like `.env.production`, `.env.bak` and `.env.old`.
- **Brute-force attempts used a password list built from the target's name.** Every
  attempt used the username `admin` on the fake WordPress login. Next to `admin123` and
  `admin2025`, attackers tried `freight`, `freight123` and the site's own domain name,
  which suggests the tool generated passwords from the target's name and domain.
- **Real exploit attempts**, including a PHPUnit remote code execution probe
  (CVE-2017-9841), a Laravel Ignition remote code execution attempt (CVE-2021-3129)
  and requests for Spring Boot actuator endpoints such as `/actuator/env` and
  `/actuator/heapdump`.
- **Most traffic was automated reconnaissance.** 829 IPs sent exactly one request,
  and the 10 busiest IPs sent 43% of all requests. No Log4Shell, SQL injection or
  cross-site scripting payloads were seen in this period.

![Attack types and top countries](docs/attack-types-countries.png)

![Most common passwords tried and most-probed paths](docs/passwords-paths.png)

*Dashboard totals include a handful of my own test requests, which is why the
results above are rounded down.*

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

### Custom domain (Cloudflare)

The honeypot is served on its own domain, with DNS managed in Cloudflare and pointed
at the Render service, so it looks like a real company site rather than an
`onrender.com` address. The app reads the first address in `X-Forwarded-For`, so the
real client IP is recorded, not a proxy's.

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

Python 3.12 · Flask · Gunicorn · PostgreSQL (psycopg 3) · Leaflet · Render · Cloudflare
