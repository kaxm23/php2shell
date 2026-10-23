#!/usr/bin/env bash
# fix-readme.sh — v0.4.0 verdict taxonomy cleanup, one-shot
set -euo pipefail
cd "$(dirname "$0")"
[[ -f README.md ]] || { echo "no README.md here"; exit 1; }
[[ -f README.md.bak ]] || cp README.md README.md.bak

python3 - <<'PYEOF'
import re, pathlib, sys

p = pathlib.Path("README.md")
s = p.read_text()
orig = s

# ── 1. Backticked verdict tokens → new names ──────────────────────────
# Order matters: rename longer/dying tokens first.
token_map = [
    ("`Poisoned`",     "`UNCONFIRMED`"),
    ("`NoLfi`",        "`NO_LFI`"),
    ("`AuthRequired`", "`AUTH_REQUIRED`"),
    ("`Crash`",        "`HTTP_ERROR`"),
    ("`Blocked`",      "`HTTP_ERROR`"),
    ("`Miss`",         "`UNKNOWN`"),
]
for a, b in token_map:
    s = s.replace(a, b)

# ── 2. `Rce` as verdict name — only in table-row / sentence contexts ──
# Table row:  | **`Rce`** |  →  | **`UNCONFIRMED`** |
s = s.replace("| **`Rce`** |", "| **`UNCONFIRMED`** |")
# Sample output:  "VERDICT:      Rce"  →  "VERDICT:      UNCONFIRMED"
s = s.replace("VERDICT:      Rce", "VERDICT:      UNCONFIRMED")
# Sentence:  "the tool says Rce."  →  "the tool says UNCONFIRMED."
s = s.replace('the tool says Rce.', 'the tool says UNCONFIRMED.')
# Sentence:  "If you have `Rce`,"  →  "If both markers appear,"
s = s.replace("If you have `Rce`,", "If both markers appear,")
# Sentence:  "Only `Rce` is a positive finding."  (dedupe in next step)

# ── 3. Collapse duplicate assertion lines ─────────────────────────────
dup_blocks = [
    # (pattern, replacement)  — pattern is literal
    (
        "**Only `Rce` is a positive finding.**\n"
        "**Only `Rce` is a positive finding.**",
        "**This build has no `CONFIRMED` verdict. `UNCONFIRMED` is not a positive finding.**",
    ),
    (
        "**Repeat until `Rce` or you've exhausted all options.**\n"
        "**Repeat until `Rce` or you've exhausted all options.**",
        "**Repeat until both markers appear or you've exhausted all options.**",
    ),
    (
        "**`NO_LFI` is not `Patched`. `NO_LFI` is not \"not vulnerable.\"**\n"
        "**`NO_LFI` is not `Patched`. `NO_LFI` is not \"not vulnerable.\"**",
        "**`NO_LFI` is not `Patched`. `NO_LFI` is not \"not vulnerable.\"**",
    ),
]
for a, b in dup_blocks:
    s = s.replace(a, b)

# ── 4. Prose sentence fixes ───────────────────────────────────────────
prose = [
    (
        "Once you have `UNCONFIRMED`, run a **proof-of-impact** command — not just `id`:",
        "Once both markers appear, add an **out-of-band proof** — not just `id`:",
    ),
    (
        "If the first attempt gives `UNCONFIRMED` (not `Rce`), try these in order:",
        "If the first attempt gives `UNCONFIRMED` with no marker pair, try these in order:",
    ),
    ("If `UNCONFIRMED`:", "If both markers appear:"),
    (
        "If `UNCONFIRMED`, move to Step 6 (Troubleshooting).",
        "If `UNCONFIRMED` with no marker pair, move to Step 6 (Troubleshooting).",
    ),
    (
        "If you got `UNCONFIRMED` at Step 4, try in order:",
        "If you got `UNCONFIRMED` with no marker pair at Step 4, try in order:",
    ),
    (
        "distinguishes `NO_LFI` from `UNCONFIRMED` from `Rce`.",
        "distinguishes `NO_LFI` from `UNCONFIRMED`.",
    ),
    (
        "distinguishes `NO_LFI` from `UNCONFIRMED` from `Rce`. That's the niche.",
        "distinguishes `NO_LFI` from `UNCONFIRMED`. That's the niche.",
    ),
    (
        "**A report needs evidence, not just \"the tool says UNCONFIRMED.\"**",
        "**A report needs evidence, not just \"the tool says UNCONFIRMED.\"**\n"
        "**`UNCONFIRMED` alone is not proof of execution — add an OOB channel.**",
    ),
    (
        "Because `UNCONFIRMED` alone proves *nothing* about whether the target is",
        "Because `UNCONFIRMED` alone proves *nothing* about whether the target is",
    ),
    (
        "**Not detected by php2shell.** You will see `UNCONFIRMED` with no explanation.",
        "**Not detected by php2shell.** You will see `UNCONFIRMED` with no explanation.",
    ),
    (
        "6. **Retries/tuning** — 5 escalation paths when `UNCONFIRMED`",
        "6. **Retries/tuning** — 5 escalation paths when `UNCONFIRMED`",
    ),
]

# ── 5. Rename troubleshooting headings + merge the two HTTP_ERROR ones ─
s = s.replace("### `UNCONFIRMED` verdict",   "### `UNCONFIRMED` verdict")
s = s.replace("### `NO_LFI` verdict",         "### `NO_LFI` verdict")
s = s.replace("### `AUTH_REQUIRED` verdict",  "### `AUTH_REQUIRED` verdict")
s = s.replace("### `UNKNOWN` verdict",        "### `UNKNOWN` verdict")

# Merge Blocked + Crash troubleshooting subsections into one HTTP_ERROR block
s = s.replace(
    "### `HTTP_ERROR` verdict\n",
    "### `HTTP_ERROR` verdict\n\n> Applies to **both** 5xx/timeout/reset *and* non-login 3xx (WAF/gate/CDN).\n",
    1,
)
# If the two old headings are now `### HTTP_ERROR verdict` (both), merge them
s = re.sub(
    r"### `HTTP_ERROR` verdict\n(.*?)\n### `HTTP_ERROR` verdict\n",
    r"### `HTTP_ERROR` verdict\n\1\n",
    s, flags=re.S,
)

# ── 6. Replace JSON example block value ───────────────────────────────
s = re.sub(
    r'"command": "id; hostname",',
    '"command": "echo PHP_TRANSPORT_PROBE_OK",',
    s,
)
s = re.sub(
    r'"marker_output": "uid=33\(www-data\) gid=33\(www-data\) groups=33\(www-data\)\\nlab-web01\\n",',
    '"marker_output": "PHP_TRANSPORT_PROBE_OK",\n  "execution_confirmed": false,\n  "retry_after": null,',
    s,
)

# ── 7. Insert ## Verdicts section before ## All verdicts explained ────
verdicts_section = """## Verdicts

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

"""
if "## Verdicts" not in s:
    s = s.replace("## All verdicts explained", verdicts_section + "## All verdicts explained", 1)

# ── 8. Also update the "All verdicts explained" 9-row table verbatim ─
old_table_rows = re.compile(
    r"\| \*\*`UNCONFIRMED`\*\* \| Command output observed[^\n]*\n"
    r"\| \*\*`UNCONFIRMED`\*\* \| Race succeeded and LFI fired[^\n]*\n"
    r"\| \*\*`NO_LFI`\*\*[^\n]*\n"
    r"\| \*\*`HTTP_ERROR`\*\* \| 5xx[^\n]*\n"
    r"\| \*\*`AUTH_REQUIRED`\*\*[^\n]*\n"
    r"\| \*\*`HTTP_ERROR`\*\* \| 3xx redirect[^\n]*\n"
    r"\| \*\*`UNKNOWN`\*\*[^\n]*\n"
)
new_table_rows = """| **`UNCONFIRMED`** | Marker pair present; reflection cannot be ruled out | **Inconclusive — NOT confirmed RCE** | Add an OOB channel (Step 5) |
| **`NO_LFI`** | Race succeeded, no `--lfi` supplied | **Untested** | Run again with `--lfi` |
| **`HTTP_ERROR`** | 5xx / timeout / non-login 3xx / reset | **Needs investigation** | Retry once, then inspect |
| **`AUTH_REQUIRED`** | 401, or 3xx to a login path | **Blocked by auth** | Obtain a real SID, use `--sid` |
| **`RATE_LIMITED`** | 429, or exhausted rate-limit header | **Blocked by rate limit** | Slow down: `--lfi-workers 1 --lfi-interval 500` |
| **`UNKNOWN`** | Transport error or unrecognised response | **Not applicable** | Double-check URL, rerun with `-v` |
"""
# only substitute if the old rows are still present in a recognizable form
s = re.sub(
    r"\| \*\*`Rce`\*\*[^\n]*\n\| \*\*`UNCONFIRMED`\*\* \| Race succeeded and LFI fired[^\n]*\n"
    r"\| \*\*`NO_LFI`\*\*[^\n]*\n\| \*\*`HTTP_ERROR`\*\*[^\n]*\n"
    r"\| \*\*`AUTH_REQUIRED`\*\*[^\n]*\n\| \*\*`HTTP_ERROR`\*\* \| 3xx[^\n]*\n"
    r"\| \*\*`UNKNOWN`\*\*[^\n]*\n",
    new_table_rows, s,
)

# ── 9. Update the duplicated-assertions tally at bottom of README ────
s = s.replace(
    '- **"Only `Rce` is a positive finding"** — 2 times',
    '- **"This build has no `CONFIRMED` verdict"** — 2 times',
)
s = s.replace(
    '- **"Repeat until `Rce`"** — 2 times',
    '- **"Repeat until both markers appear"** — 2 times',
)

# ── 10. Changelog line ───────────────────────────────────────────────
s = s.replace(
    "- **Add:** `--lfi-max-attempts` cap",
    "- **Add:** `--lfi-max-attempts` cap\n"
    "- **Remove:** RCE verdict; two-marker hit now yields `UNCONFIRMED` (reflection cannot be excluded)",
)

# ── 11. Write, report delta ──────────────────────────────────────────
if s == orig:
    print("[!] no changes — README may already be clean")
    sys.exit(0)
p.write_text(s)
print(f"[ok] README.md updated ({len(s.splitlines())} lines)")
PYEOF

echo
echo "==> Straggler scan:"
if grep -nE '\bRce\b|`Poisoned`|`Crash`|`Blocked`|`Miss`|`NoLfi`' README.md; then
    echo
    echo "    ^^ remaining hits — inspect manually (RCE in prose about technique is OK)"
else
    echo "    [ok] clean"
fi

echo
echo "==> Key assertions:"
for pat in '^## Verdicts' '"verdict": "UNCONFIRMED"' 'PHP_TRANSPORT_PROBE_OK' '"execution_confirmed": false'; do
    n=$(grep -cE "$pat" README.md || true)
    printf '  %-40s %s\n' "$pat" "$n hit(s)"
done