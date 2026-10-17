#!/usr/bin/env python3
import os
os.environ["PYTHONIOENCODING"] = "UTF8"
os.environ["COLORTERM"] = "truecolor"
os.environ["TERM"] = "xterm-256color"

import sys
import time
import json
import random
import string
import hashlib
import argparse
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse, urljoin

import httpx
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED, HEAVY, DOUBLE, SIMPLE
from rich.theme import Theme
from rich.align import Align

THEME = Theme({
    "info": "bright_cyan",
    "warn": "bold bright_yellow",
    "danger": "bold bright_red",
    "success": "bold bright_green",
    "muted": "dim white",
    "accent": "bold magenta",
    "accent2": "bold bright_blue",
    "critical": "bold white on red",
})

console = Console(
    theme=THEME,
    force_terminal=True,
    color_system="truecolor",
    legacy_windows=False,
    highlight=False,
)

CONFIG_FILENAME = "config.json"

DEFAULT_CONFIG = {
    "rate_limit_per_minute": 60,
    "min_delay_seconds": 0.5,
    "timeout_seconds": 12.0,
    "max_requests_per_scan": 500,
}

CLOAKING_PARAMS = ["utm_source", "callback", "format", "lang", "debug"]
CLOAKING_SEPARATORS = ["%3B", "%26"]
CONFIRM_MAX_REFLECTIONS = 5
POISON_SETTLE_SECONDS = 5.0
MAX_CONSECUTIVE_ERRORS = 10

BASE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close",
}

UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-For", "X-Forwarded-Prefix",
    "X-Forwarded-Server", "X-Real-IP", "X-Original-URL", "X-Rewrite-URL",
    "X-Original-Host", "X-Original-Forwarded-For", "X-Host",
    "X-HTTP-Host-Override", "X-HTTP-Method-Override", "X-Backend-Host",
    "X-Proxy-Host", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
    "X-Originating-IP", "Forwarded", "True-Client-IP",
    "CF-Connecting-IP", "CF-Connecting-IP6", "Fastly-Client-IP",
    "X-Akamai-Edge-IP", "X-Cluster-Client-IP",
]

UNKEYED_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "callback", "cb", "jsonp", "format", "lang", "locale", "theme",
    "debug", "test", "preview", "cache", "no-cache",
    "redirect", "return", "next", "url", "ref", "referer",
    "gclid", "fbclid", "msclkid", "_ga", "yclid",
]

CACHE_HEADERS_OF_INTEREST = [
    "x-cache", "x-cache-status", "x-cache-hit", "x-cache-lookup",
    "x-cache-hits", "cf-cache-status", "cf-ray", "age",
    "x-varnish", "x-varnish-cache", "x-proxy-cache", "x-proxy-id",
    "x-fastly-request-id", "x-served-by", "x-timer",
    "x-akamai-transformed", "x-cdn", "via", "x-edge-location",
    "x-sucuri-id", "x-sucuri-cache", "x-cacheable", "cache-control",
    "eo-cache-status", "cdn-cache-status", "x-check-cacheable",
    "x-cache-key", "x-true-cache-key", "x-debug",
    "fastly-debug", "fastly-debug-path", "fastly-debug-ttl",
    "x-cache-generation", "x-milestones", "x-transaction-id", "x-remap",
]

CDN_FINGERPRINTS = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "cf-connecting-ip",
                   "server: cloudflare", "__cfduid", "cf-request-id"],
    "Akamai": ["x-akamai-transformed", "x-check-cacheable", "x-cache-key",
               "x-true-cache-key", "x-serial", "akamai-ghost", "akamai-grn",
               "x-akamai-request-id", "x-akamai-session-info"],
    "Fastly": ["x-fastly-request-id", "fastly-debug", "fastly-debug-path",
               "fastly-debug-ttl", "x-served-by", "x-cache-hits",
               "fastly-client-ip", "fastly-ssl"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront",
                       "x-amz-cf-request-id"],
    "Varnish": ["x-varnish", "x-varnish-cache", "x-varnish-cacheable",
                "x-varnish-hit"],
    "Squid": ["x-cache-lookup", "server: squid"],
    "Azure Front Door": ["x-azure-ref", "x-fd-healthprobe", "azurefd",
                         "x-azure-requestchain", "x-azure-clientip"],
    "Google Cloud CDN": ["x-cloud-trace-context", "x-goog-generation",
                         "server: gws"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri",
               "x-sucuri-block"],
    "Imperva / Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
    "Traffic Server (ATS)": ["c-cache-generation", "x-milestones",
                             "x-transaction-id", "x-remap"],
    "Tencent EdgeOne": ["eo-cache-status", "eo-log-uuid", "eo-cache-key",
                        "server: edgeone"],
    "Alibaba Cloud CDN": ["ali-swift-global-savetime"],
    "BunnyCDN": ["server: bunnycdn", "cdn-pullzone", "cdn-requestid",
                 "cdn-uid"],
    "KeyCDN": ["server: keycdn", "x-shield", "x-edge-location"],
    "StackPath": ["server: stackpath", "x-sp-cache", "x-sp-request-id"],
    "Gcore": ["server: gcore", "x-gcore-request-id", "x-gcore-cache"],
    "ArvanCloud": ["server: arvancloud", "ar-request-id", "ar-cache"],
    "VNCDN": ["server: vncdn", "x-vncdn-cache"],
    "Netlify": ["server: netlify", "x-nf-request-id", "x-nf-render-mode"],
    "Vercel": ["server: vercel", "x-vercel-id", "x-vercel-cache",
               "x-vercel-execution"],
    "Fly.io": ["server: fly", "fly-request-id", "fly-cache-status"],
    "Render": ["server: render", "x-render-origin-server", "rndr-id"],
    "Railway": ["server: railway", "x-railway-request-id"],
    "Deno Deploy": ["server: deno", "x-deno-request-id"],
    "Firebase Hosting": ["server: firebase", "x-firebase-cache"],
    "GitHub Pages": ["server: github.com", "x-github-request-id"],
    "Shopify": ["x-shopid", "x-shardid", "x-shopify-stage"],
    "WordPress / WP Engine": ["x-powered-by: wp engine", "wpe-backend",
                              "wpe-request-id"],
    "Nginx (reverse proxy)": ["server: nginx"],
    "HAProxy": ["server: haproxy"],
    "Envoy": ["server: envoy", "x-envoy-upstream-service-time"],
    "Apache Traffic Server": ["server: ats"],
    "LiteSpeed": ["server: litespeed"],
    "OpenResty": ["server: openresty"],
    "Caddy": ["server: caddy"],
    "Tengine": ["server: tengine"],
}

STATIC_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".txt",
]

STATIC_DIRECTORIES = [
    "/static/", "/assets/", "/media/", "/uploads/", "/wp-content/",
    "/wp-includes/", "/cdn/", "/public/", "/files/", "/images/",
    "/img/", "/fonts/", "/scripts/", "/styles/", "/dist/", "/build/",
]

DELIMITERS = [";", "%3B", "%3b", ";;", ";%00", "%00"]

MAX_RETRIES_429 = 3
MAX_CRAWL_PATHS = 30


def load_config() -> dict:
    path = Path(CONFIG_FILENAME)
    cfg = dict(DEFAULT_CONFIG)
    if not path.exists():
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(DEFAULT_CONFIG, fh, indent=4)
            console.print(
                f"[info]ℹ Created default config →[/info] [bright_white]{CONFIG_FILENAME}[/bright_white]"
            )
        except Exception as exc:
            console.print(f"[warn]⚠ Could not create config: {exc}[/warn]")
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)
        for key in DEFAULT_CONFIG:
            if key in user_cfg:
                cfg[key] = user_cfg[key]
        console.print(
            f"[success]✔ Config loaded →[/success] [bright_white]{CONFIG_FILENAME}[/bright_white] "
            f"[muted]({cfg['rate_limit_per_minute']} req/min)[/muted]"
        )
    except Exception as exc:
        console.print(f"[warn]⚠ Invalid config ({exc}) — using defaults.[/warn]")
    return cfg


def rnd(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def cache_buster() -> str:
    return f"_cb={rnd(12)}"


def add_query(url: str, qs: str) -> str:
    p = urlparse(url)
    merged = "&".join(filter(None, [p.query, qs]))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, merged, p.fragment))


def replace_path(url: str, new_path: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, p.fragment))


def short_hash(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()[:12]


def truncate(s: str, n: int = 48) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def classify_cache_status(headers: httpx.Headers) -> str:
    for key in (
        "x-cache", "x-cache-status", "cf-cache-status", "x-cache-lookup",
        "x-cache-hit", "eo-cache-status", "cdn-cache-status", "x-vercel-cache",
        "fly-cache-status", "x-sp-cache", "ar-cache", "x-vncdn-cache",
        "x-gcore-cache", "x-keycdn-cache",
    ):
        val = headers.get(key, "").lower()
        if not val:
            continue
        if "hit" in val or val in ("true", "yes", "hit_fresh", "refreshhit"):
            return "hit"
        if "miss" in val or val in ("false", "no", "expired"):
            return "miss"
    return "unknown"


def detect_html_context(body: str, canary: str) -> str:
    esc = re.escape(canary)
    if re.search(rf'<script[^>]*>[^<]*{esc}', body, re.I):
        return "script-body"
    if re.search(rf'<script[^>]*(src|href)\s*=\s*["\'][^"\']*{esc}', body, re.I):
        return "script-src"
    if re.search(rf'<link[^>]+href\s*=\s*["\'][^"\']*{esc}', body, re.I):
        return "link-href"
    if re.search(rf'<a[^>]+href\s*=\s*["\'][^"\']*{esc}', body, re.I):
        return "anchor-href"
    if re.search(rf'<form[^>]+action\s*=\s*["\'][^"\']*{esc}', body, re.I):
        return "form-action"
    if re.search(rf'<meta[^>]+content\s*=\s*["\'][^"\']*{esc}', body, re.I):
        return "meta-content"
    if re.search(rf'<iframe[^>]+src\s*=\s*["\'][^"\']*{esc}', body, re.I):
        return "iframe-src"
    return "body"


def detect_cdn_provider(headers: httpx.Headers, body: str) -> str:
    header_blob = "\n".join(f"{k.lower()}: {v}".lower() for k, v in headers.items())
    combined = header_blob + "\n" + body.lower()[:5000]

    matches = []
    for provider, fingerprints in CDN_FINGERPRINTS.items():
        score = 0
        for fp in fingerprints:
            if ":" in fp:
                key, val = fp.split(":", 1)
                key = key.strip().lower()
                val = val.strip().lower()
                if key in headers and val in headers[key].lower():
                    score += 2
            else:
                if fp in combined:
                    score += 1
        if score >= 2:
            matches.append((provider, score))

    if not matches:
        return "unknown"

    matches.sort(key=lambda x: x[1], reverse=True)
    if len(matches) > 1 and matches[0][1] == matches[1][1]:
        return f"{matches[0][0]} / {matches[1][0]} (ambiguous)"
    return matches[0][0]


@dataclass
class CacheInfo:
    present: bool = False
    provider: str = "unknown"
    ttl_hint: Optional[str] = None
    headers: dict = field(default_factory=dict)


@dataclass
class Finding:
    phase: str
    kind: str
    severity: str
    input: str
    evidence: str
    context: str = ""
    details: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_STYLE = {
    "critical": "critical", "high": "danger", "medium": "warn",
    "low": "info", "info": "muted",
}


class AdaptiveClient:
    def __init__(self, timeout, proxy, insecure, rate_limit_per_minute,
                 min_delay, max_requests):
        self.inner = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=not insecure,
            proxy=proxy,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
        )
        self.rate_limit_per_second = rate_limit_per_minute / 60.0
        self.base_delay = max(min_delay, 1.0 / self.rate_limit_per_second)
        self.current_delay = self.base_delay
        self.max_requests = max_requests
        self.request_count = 0
        self.consecutive_errors = 0
        self.last_request_time = 0.0

    def _enforce_rate(self):
        if self.request_count >= self.max_requests:
            raise RuntimeError(
                f"Request cap reached ({self.max_requests}). Aborting scan."
            )
        now = time.time()
        elapsed = now - self.last_request_time
        target = max(self.current_delay, 1.0 / self.rate_limit_per_second)
        if elapsed < target:
            time.sleep(target - elapsed)

    def _backoff(self):
        self.consecutive_errors += 1
        if self.consecutive_errors >= 3:
            self.current_delay = min(self.current_delay * 2.0, 8.0)
            console.print(
                f"  [warn]⚠ Backoff engaged → {self.current_delay:.2f}s "
                f"(errors: {self.consecutive_errors})[/warn]"
            )

    def _recover(self):
        self.consecutive_errors = 0
        if self.current_delay > self.base_delay:
            self.current_delay = max(self.current_delay * 0.9, self.base_delay)

    def request(self, method, url, **kwargs):
        self._enforce_rate()
        headers = kwargs.pop("headers", {})
        merged = {**BASE_HEADERS, **headers}

        for attempt in range(MAX_RETRIES_429 + 1):
            try:
                resp = self.inner.request(method, url, headers=merged, **kwargs)
            except httpx.HTTPError as exc:
                console.print(
                    f"  [danger]✖ request failed:[/danger] [muted]{exc}[/muted]"
                )
                self._backoff()
                if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    raise RuntimeError(
                        "Too many consecutive errors — target may be blocking us."
                    )
                return None

            self.request_count += 1
            self.last_request_time = time.time()

            if resp.status_code == 429 and attempt < MAX_RETRIES_429:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                console.print(
                    f"  [warn]⚠ 429 received — sleeping {retry_after}s "
                    f"(attempt {attempt + 1}/{MAX_RETRIES_429})[/warn]"
                )
                time.sleep(retry_after)
                continue

            if resp.status_code in (502, 503, 504):
                self._backoff()
            else:
                self._recover()

            return resp

        return None

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def close(self):
        self.inner.close()


def header_line(phase: str, title: str):
    console.print()
    console.rule(
        f"[bold magenta]{phase}[/bold magenta] · [bold bright_cyan]{title}[/bold bright_cyan]",
        style="bright_magenta", align="left",
    )
    console.print()


def render_banner(cfg: dict, deep: bool):
    mode = "DEEP SCAN" if deep else "NORMAL SCAN"
    mode_color = "bright_red" if deep else "bright_green"
    banner = Text.assemble(
        ("CACHE POISONING & DECEPTION DETECTOR\n", "bold bright_magenta"),
        ("Mode: ", "dim"), (mode, f"bold {mode_color}"),
        ("   Rate limit: ", "dim"),
        (f"{cfg['rate_limit_per_minute']} req/min", "bright_cyan"),
        ("   Min delay: ", "dim"),
        (f"{cfg['min_delay_seconds']}s", "bright_cyan"),
        ("   Request cap: ", "dim"),
        (f"{cfg['max_requests_per_scan']}", "bright_cyan"),
        ("\n", ""),
    )
    console.print(Panel(
        Align.center(banner),
        border_style="bright_magenta", box=DOUBLE, padding=(1, 4),
    ))


def render_cache_panel(info: CacheInfo, url: str):
    body = Group(
        Text.assemble(("Target     : ", "bold cyan"), (url, "bright_white")),
        Text.assemble(("Cache      : ", "bold cyan"),
                      ("PRESENT" if info.present else "NOT DETECTED",
                       "bright_green" if info.present else "bright_red")),
        Text.assemble(("Provider   : ", "bold cyan"), (info.provider, "bright_yellow")),
        Text.assemble(("TTL hint   : ", "bold cyan"), (info.ttl_hint or "—", "muted")),
    )
    if info.headers:
        tbl = Table(box=SIMPLE, border_style="bright_cyan",
                    show_header=True, padding=(0, 1))
        tbl.add_column("Header", style="cyan", no_wrap=True)
        tbl.add_column("Value", style="bright_white")
        for k, v in info.headers.items():
            tbl.add_row(k, truncate(v, 60))
        body = Group(body, Text(""), tbl)
    console.print(Panel(
        body,
        title="[bold bright_magenta]◈ CACHE LAYER ◈[/bold bright_magenta]",
        border_style="bright_magenta", box=ROUNDED, padding=(0, 2),
    ))


def detect_cache(client: AdaptiveClient, url: str) -> CacheInfo:
    header_line("PHASE 1", "Cache Layer Detection")
    info = CacheInfo()
    resp = client.get(add_query(url, cache_buster()))
    if not resp:
        console.print("[danger]✖ Unable to reach target.[/danger]")
        return info

    for h in CACHE_HEADERS_OF_INTEREST:
        if h in resp.headers:
            info.headers[h] = resp.headers[h]

    info.provider = detect_cdn_provider(resp.headers, resp.text)

    try:
        if int(resp.headers.get("age", "0")) > 0:
            info.present = True
    except ValueError:
        pass
    if info.headers:
        info.present = True

    if "cache-control" in resp.headers:
        info.ttl_hint = resp.headers["cache-control"]

    render_cache_panel(info, url)
    return info


def detect_spa(client: AdaptiveClient, url: str) -> bool:
    base = client.get(url)
    if not base:
        return False
    resp = client.get(replace_path(url, "/" + rnd(16)))
    if not resp:
        return False
    return resp.status_code == 200 and short_hash(resp.content) == short_hash(base.content)


def crawl_static_paths(client: AdaptiveClient, base_url: str) -> list[str]:
    header_line("CRAWL", "Static Path Discovery")
    resp = client.get(base_url)
    if not resp:
        console.print("[warn]⚠ Could not fetch base page — skipping crawl.[/warn]")
        return []

    links = set(re.findall(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', resp.text, re.I))
    base_host = urlparse(base_url).netloc

    filtered: list[str] = []
    seen_paths: set[str] = set()

    for link in links:
        link = link.strip()
        if not link or link.startswith(("javascript:", "mailto:", "data:", "#")):
            continue
        absolute = urljoin(base_url, link)
        parsed = urlparse(absolute)
        if parsed.netloc != base_host:
            continue

        path = parsed.path
        if not path or path == "/":
            continue

        is_static_ext = any(path.lower().endswith(ext) for ext in STATIC_EXTENSIONS)
        is_static_dir = any(d in path.lower() for d in STATIC_DIRECTORIES)

        if not (is_static_ext or is_static_dir):
            continue

        if path in seen_paths:
            continue
        seen_paths.add(path)

        scheme = urlparse(base_url).scheme
        filtered.append(f"{scheme}://{base_host}{path}")
        if len(filtered) >= MAX_CRAWL_PATHS:
            break

    if not filtered:
        console.print("[muted]◦ No static paths found on base page.[/muted]")
    else:
        console.print(f"[info]▸ Discovered {len(filtered)} static path(s):[/info]")
        for p in filtered:
            console.print(f"  [cyan]→[/cyan] {truncate(p, 90)}")

    return filtered


def phase_header_reflection(client, url):
    header_line("PHASE 2", "Unkeyed Header Reflection")
    findings = []
    base = client.get(add_query(url, cache_buster()))
    if not base:
        return findings
    base_len = len(base.content)
    with console.status("[info]Probing headers…[/info]", spinner="dots12"):
        for h in UNKEYED_HEADERS:
            canary = f"cpoison-{rnd(6)}.example.com"
            resp = client.get(add_query(url, cache_buster()), headers={h: canary})
            if not resp:
                continue
            if canary in resp.text:
                ctx = detect_html_context(resp.text, canary)
                sev = "high" if ctx != "body" else "medium"
                findings.append(Finding(
                    phase="Header Reflection", kind="reflection",
                    severity=sev, input=f"{h} @ {urlparse(url).path or '/'}",
                    evidence=f"Canary reflected ({ctx})", context=ctx,
                    details=f"Δlen={len(resp.content) - base_len:+d}B",
                ))
                console.print(f"  [warn]⚠[/warn] [cyan]{h}[/cyan] → [warn]{ctx}[/warn]")
            for rk, rv in resp.headers.items():
                if canary in rv:
                    findings.append(Finding(
                        phase="Header Reflection", kind="reflection",
                        severity="medium", input=f"{h} @ {urlparse(url).path or '/'}",
                        evidence=f"Reflected in response header '{rk}'",
                        context="response-header",
                        details=f"value={truncate(rv, 60)}",
                    ))
                    break
    return findings


def phase_param_reflection(client, url):
    header_line("PHASE 3", "Unkeyed Query-Parameter Reflection")
    findings = []
    base = client.get(add_query(url, cache_buster()))
    if not base:
        return findings
    base_len = len(base.content)
    with console.status("[info]Probing query parameters…[/info]", spinner="dots12"):
        for p in UNKEYED_PARAMS:
            canary = f"cpoison-{rnd(6)}"
            resp = client.get(add_query(url, f"{p}={canary}&{cache_buster()}"))
            if not resp:
                continue
            if canary in resp.text:
                ctx = detect_html_context(resp.text, canary)
                sev = "high" if ctx != "body" else "medium"
                findings.append(Finding(
                    phase="Parameter Reflection", kind="reflection",
                    severity=sev, input=f"?{p}= @ {urlparse(url).path or '/'}",
                    evidence=f"Canary reflected ({ctx})", context=ctx,
                    details=f"Δlen={len(resp.content) - base_len:+d}B",
                ))
                console.print(f"  [warn]⚠[/warn] [cyan]?{p}=[/cyan] → [warn]{ctx}[/warn]")
    return findings


def phase_param_cloaking(client, url):
    header_line("PHASE 4", "Parameter Cloaking")
    findings = []
    base = client.get(add_query(url, cache_buster()))
    if not base:
        return findings
    base_len = len(base.content)
    with console.status("[info]Testing parameter cloaking…[/info]", spinner="dots12"):
        for p in CLOAKING_PARAMS:
            malicious = f"POISON-{rnd(6)}"
            for sep in CLOAKING_SEPARATORS:
                cloaked = f"{p}=benign{sep}{p}={malicious}"
                resp = client.get(add_query(url, f"{cloaked}&{cache_buster()}"))
                if not resp:
                    continue
                if malicious in resp.text:
                    findings.append(Finding(
                        phase="Parameter Cloaking", kind="cloaking",
                        severity="high",
                        input=f"?{p}= via {sep} @ {urlparse(url).path or '/'}",
                        evidence="Origin used second value while cache keyed on first",
                        context="parameter-splitting",
                        details=f"Δlen={len(resp.content) - base_len:+d}B",
                    ))
                    console.print(f"  [warn]⚠[/warn] [cyan]{p}[/cyan] via [magenta]{sep}[/magenta]")
                    break
    return findings


def phase_normalization(client, url):
    header_line("PHASE 5", "Cache-Key Normalization")
    findings = []
    base_resp = client.get(add_query(url, cache_buster()))
    if not base_resp:
        return findings
    base_hash = short_hash(base_resp.content)
    parsed = urlparse(url)
    base_path = parsed.path or "/"
    variants = [
        (base_path + "/./", "trailing-dot"),
        (base_path + "/../" + base_path.lstrip("/"), "dot-traversal"),
        (base_path + "//", "double-slash"),
        (base_path.upper(), "uppercase"),
        (base_path + "/.", "dot-end"),
        (re.sub(r"/+", "/", base_path + "//"), "collapse"),
    ]
    with console.status("[info]Testing normalization variants…[/info]", spinner="dots12"):
        for variant_path, label in variants:
            resp = client.get(replace_path(add_query(url, cache_buster()), variant_path))
            if not resp:
                continue
            if short_hash(resp.content) == base_hash and resp.status_code == 200:
                findings.append(Finding(
                    phase="Normalization", kind="normalization",
                    severity="medium", input=f"{variant_path} @ {base_path}",
                    evidence=f"Variant '{label}' returned identical body",
                    context="cache-key-collision",
                    details=f"status={resp.status_code} | hash={short_hash(resp.content)}",
                ))
                console.print(f"  [warn]⚠[/warn] normalization: [cyan]{label}[/cyan]")
    return findings


def phase_cache_deception(client, url):
    header_line("PHASE 6", "Web Cache Deception")
    findings = []
    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/") or "/"
    with console.status("[info]Testing deception payloads…[/info]", spinner="dots12"):
        for ext in STATIC_EXTENSIONS:
            test_path = f"{base_path}{ext}"
            resp = client.get(replace_path(add_query(url, cache_buster()), test_path))
            if not resp:
                continue
            if (
                classify_cache_status(resp.headers) == "hit"
                and "text/html" in resp.headers.get("content-type", "").lower()
                and resp.status_code == 200
            ):
                findings.append(Finding(
                    phase="Cache Deception", kind="deception",
                    severity="high", input=f"{test_path}",
                    evidence="Static-suffixed path cached, serves dynamic content",
                    context=f"cache=hit | path={base_path}",
                    details=f"status={resp.status_code} | ext={ext}",
                ))
                console.print(f"  [warn]⚠[/warn] deception via [magenta]{ext}[/magenta]")
        for d in DELIMITERS:
            test_path = f"{base_path}{d}deception.css"
            resp = client.get(replace_path(add_query(url, cache_buster()), test_path))
            if not resp:
                continue
            if (
                classify_cache_status(resp.headers) == "hit"
                and "text/html" in resp.headers.get("content-type", "").lower()
            ):
                findings.append(Finding(
                    phase="Cache Deception", kind="deception",
                    severity="high", input=f"{base_path}{d}…",
                    evidence=f"Delimiter '{d}' confused the cache",
                    context="delimiter-confusion",
                    details=f"status={resp.status_code}",
                ))
                console.print(f"  [warn]⚠[/warn] deception via [magenta]{d}[/magenta]")
                break
    return findings


def phase_poison_confirm(client, url, findings):
    header_line("PHASE 7", "Poison Confirmation")
    confirmations = []
    high = [f for f in findings if f.kind == "reflection" and f.severity in ("high", "medium")]
    if not high:
        console.print("[muted]No high-severity reflections — skipping.[/muted]")
        return confirmations
    for f in high[:CONFIRM_MAX_REFLECTIONS]:
        canary = f"POISON-{rnd(6)}.example.com"
        buster = cache_buster()
        poison_url = add_query(url, buster)
        headers = {}
        if " @ " in f.input:
            inp = f.input.split(" @ ")[0]
        else:
            inp = f.input
        if inp.startswith("?"):
            param = inp.split(" ")[0][1:].rstrip("=")
            poison_url = add_query(url, f"{param}={canary}&{buster}")
        else:
            headers[inp] = canary
        r1 = client.get(poison_url, headers=headers)
        if not r1 or canary not in r1.text:
            console.print(f"  [muted]◦ {inp}: not reflected, skipping[/muted]")
            continue
        time.sleep(POISON_SETTLE_SECONDS)
        r2 = client.get(poison_url)
        persisted = r2 is not None and canary in r2.text
        r3 = client.get(add_query(url, cache_buster()))
        leaked = r3 is not None and canary in r3.text
        if persisted and not leaked:
            confirmations.append(Finding(
                phase="Poison Confirmation", kind="poison_confirm",
                severity="critical", input=f.input,
                evidence="Poison persisted in cache under its buster",
                context=f"cache={classify_cache_status(r2.headers)}",
                details=f"canary={canary} | isolated=True",
            ))
            console.print(f"  [danger]✔[/danger] {inp}: confirmed")
        elif persisted and leaked:
            confirmations.append(Finding(
                phase="Poison Confirmation", kind="poison_confirm",
                severity="critical", input=f.input,
                evidence="Poison leaked to fresh buster — broad impact",
                context="cache-wide",
                details=f"canary={canary} | isolated=False",
            ))
            console.print(f"  [danger]✔[/danger] {inp}: escaped isolation (critical)")
        else:
            console.print(f"  [muted]◦ {inp}: did not persist[/muted]")
    return confirmations


def scan_single_path(client, path_url, args, include_spa_check=True):
    """Run full scan on a single URL and return findings list."""
    findings = []
    cache_info = detect_cache(client, path_url)

    if not cache_info.present:
        console.print(f"[muted]◦ No cache on {urlparse(path_url).path} — skipping.[/muted]")
        return findings, cache_info

    is_spa = False
    if include_spa_check:
        is_spa = detect_spa(client, path_url)
        if is_spa:
            console.print("[warn]⚠ SPA behavior on this path — normalization may false-positive.[/warn]")

    if args.headers or args.all:
        findings.extend(phase_header_reflection(client, path_url))
    if args.params or args.all:
        findings.extend(phase_param_reflection(client, path_url))
    if args.all or args.cloaking:
        findings.extend(phase_param_cloaking(client, path_url))
    if (args.all or args.normalization) and not is_spa:
        findings.extend(phase_normalization(client, path_url))
    if args.all or args.deception:
        findings.extend(phase_cache_deception(client, path_url))
    if args.confirm or args.all:
        findings.extend(phase_poison_confirm(client, path_url, findings))

    return findings, cache_info


def render_findings(findings: list[Finding]):
    if not findings:
        console.print()
        console.print(Panel(
            Text("No findings.\nThe target either does not cache, "
                 "does not reflect unkeyed inputs, or is protected.",
                 style="bright_green", justify="center"),
            title="[bold bright_green]✓ SCAN COMPLETE[/bold bright_green]",
            border_style="bright_green", box=DOUBLE, padding=(0, 2),
        ))
        return

    findings_sorted = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
    tbl = Table(
        title="[bold bright_magenta]✦ FINDINGS ✦[/bold bright_magenta]",
        border_style="bright_cyan", box=ROUNDED,
        show_lines=True, padding=(0, 1), expand=False,
    )
    tbl.add_column("#", style="dim", width=4, justify="right")
    tbl.add_column("Severity", width=12, justify="center")
    tbl.add_column("Kind", style="bold cyan", width=20)
    tbl.add_column("Input", style="bright_yellow", width=34)
    tbl.add_column("Evidence", style="bright_white", width=50)
    tbl.add_column("Details", style="muted", width=42)
    for i, f in enumerate(findings_sorted, 1):
        style = SEV_STYLE.get(f.severity, "white")
        tbl.add_row(
            str(i), Text(f.severity.upper(), style=style),
            f.kind, truncate(f.input, 34), f.evidence, truncate(f.details, 42),
        )
    console.print()
    console.print(tbl)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "   ".join(
        f"[{SEV_STYLE[s]}]{s.upper()}: {counts[s]}[/{SEV_STYLE[s]}]"
        for s in ("critical", "high", "medium", "low", "info") if s in counts
    )
    console.print(f"\n[bold]Summary:[/bold]  {summary}\n")


def render_verdict(findings, cache_present):
    if not cache_present and not findings:
        icon, desc, style = (
            "ℹ  NO CACHE DETECTED",
            "No cache layer was found on any tested path.\n"
            "Cache poisoning and deception are not applicable to this target.",
            "info",
        )
    elif any(f.severity == "critical" for f in findings):
        icon, desc, style = (
            "🔥  CRITICAL",
            "Cache poisoning confirmed on at least one path.\n"
            "This can be weaponized to serve malicious content to all users.",
            "critical",
        )
    elif any(f.severity == "high" for f in findings):
        icon, desc, style = (
            "⚡  HIGH",
            "High-severity indicators found (reflection or deception).\n"
            "Manual verification is strongly recommended.",
            "danger",
        )
    elif any(f.severity == "medium" for f in findings):
        icon, desc, style = (
            "⚠  MEDIUM",
            "Moderate indicators found — reflection without confirmed persistence,\n"
            "or normalization anomalies.",
            "warn",
        )
    elif findings:
        icon, desc, style = (
            "ℹ  INFO",
            "Low-signal findings only.",
            "info",
        )
    else:
        icon, desc, style = (
            "🛡  CLEAN",
            "No indicators of cache poisoning or deception.",
            "success",
        )
    console.print(Panel(
        Text.assemble((f"{icon}\n\n", style), (desc, "dim white")),
        title=f"[{style}]◈ VERDICT ◈[/{style}]",
        border_style=style, box=HEAVY, padding=(1, 3),
    ))


def export_report(findings, cache_infos, url, fmt, cfg, deep):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"cpoison-report-{ts}.{fmt}"
    payload = {
        "tool": "Cache Poisoning & Deception Detector",
        "version": "1.3",
        "mode": "deep" if deep else "normal",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": url,
        "config": cfg,
        "paths_scanned": [
            {
                "url": u,
                "cache_present": ci.present,
                "provider": ci.provider,
                "ttl_hint": ci.ttl_hint,
                "headers": ci.headers,
            }
            for u, ci in cache_infos.items()
        ],
        "summary": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "findings": [asdict(f) for f in findings],
    }
    if fmt == "json":
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    elif fmt == "md":
        lines = [
            f"# Cache Poisoning Report — {url}",
            "",
            f"**Mode:** {payload['mode']}",
            f"**Generated:** {payload['timestamp']}",
            f"**Paths scanned:** {len(cache_infos)}",
            f"**Rate limit:** {cfg['rate_limit_per_minute']} req/min",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, cnt in payload["summary"].items():
            lines.append(f"| {sev.upper()} | {cnt} |")
        lines += ["", "## Paths", ""]
        for u, ci in cache_infos.items():
            lines.append(
                f"- `{u}` — cache: {ci.present}, provider: {ci.provider}"
            )
        lines += ["", "## Findings", ""]
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. [{f.severity.upper()}] {f.kind} — {f.input}")
            lines.append("")
            lines.append(f"- **Evidence:** {f.evidence}")
            lines.append(f"- **Context:** {f.context or '—'}")
            lines.append(f"- **Details:** {f.details or '—'}")
            lines.append(f"- **Timestamp:** {f.timestamp}")
            lines.append("")
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    return filename


def run(args, cfg, deep):
    render_banner(cfg, deep)
    client = AdaptiveClient(
        timeout=cfg["timeout_seconds"],
        proxy=args.proxy,
        insecure=args.insecure,
        rate_limit_per_minute=cfg["rate_limit_per_minute"],
        min_delay=cfg["min_delay_seconds"],
        max_requests=cfg["max_requests_per_scan"],
    )

    all_findings: list[Finding] = []
    cache_infos: dict[str, CacheInfo] = {}

    try:
        base_findings, base_cache = scan_single_path(
            client, args.url, args, include_spa_check=True
        )
        all_findings.extend(base_findings)
        cache_infos[args.url] = base_cache

        if not deep:
            if not base_cache.present:
                console.print()
                console.print(Panel(
                    Text.assemble(
                        ("No cache layer was detected on this target.\n\n", "bold bright_yellow"),
                        ("Cache poisoning and deception are not applicable.\n", "dim white"),
                        ("Scan aborted to avoid false positives.\n", "dim white"),
                        ("Tip: enable Deep Scan to test static paths under this domain.", "muted"),
                    ),
                    title="[bold bright_yellow]⊘  SCAN TERMINATED[/bold bright_yellow]",
                    border_style="bright_yellow", box=HEAVY, padding=(1, 3),
                ))
            render_findings(all_findings)
            render_verdict(all_findings, cache_present=any(ci.present for ci in cache_infos.values()))
            if args.export:
                path = export_report(all_findings, cache_infos, args.url, args.export, cfg, deep)
                console.print(f"[success]✔ Report →[/success] [info]{path}[/info]\n")
            return all_findings

        paths = crawl_static_paths(client, args.url)

        if not paths:
            console.print(
                "[warn]⚠ Deep Scan found no static paths to test. "
                "Base scan results still apply.[/warn]"
            )
        else:
            for i, path_url in enumerate(paths, 1):
                console.print()
                console.print(
                    f"[bold magenta]═══ Path {i}/{len(paths)} ═══[/bold magenta] "
                    f"[bright_cyan]{truncate(path_url, 80)}[/bright_cyan]"
                )
                try:
                    path_findings, path_cache = scan_single_path(
                        client, path_url, args, include_spa_check=False
                    )
                    all_findings.extend(path_findings)
                    cache_infos[path_url] = path_cache
                except RuntimeError as exc:
                    console.print(f"[danger]✖ Stopped on path: {exc}[/danger]")
                    break

    finally:
        client.close()

    render_findings(all_findings)
    render_verdict(all_findings, cache_present=any(ci.present for ci in cache_infos.values()))

    if args.export:
        path = export_report(all_findings, cache_infos, args.url, args.export, cfg, deep)
        console.print(f"[success]✔ Report →[/success] [info]{path}[/info]\n")

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        prog="cache_poison_detector",
        description="Cache Poisoning & Deception Detector v1.3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python Cache-Poison.py
  python Cache-Poison.py --url https://target.com/ --deep --all
        """,
    )
    parser.add_argument("--url")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--params", action="store_true")
    parser.add_argument("--cloaking", action="store_true")
    parser.add_argument("--normalization", action="store_true")
    parser.add_argument("--deception", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--deep", action="store_true",
                        help="Enable Deep Scan (crawl static paths, test each)")
    parser.add_argument("--export", choices=["json", "md"])
    parser.add_argument("--proxy")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    cfg = load_config()

    if not args.url:
        raw = console.input("[cyan]▶ Target URL: [/cyan]").strip()
        while not raw or not raw.startswith(("http://", "https://")):
            console.print("[warn]⚠ URL must start with http:// or https://[/warn]")
            raw = console.input("[cyan]▶ Target URL: [/cyan]").strip()
        args.url = raw

    if not args.deep:
        answer = console.input(
            "[cyan]▶ Enable Deep Scan? Crawl static paths and test each [y/N]: [/cyan]"
        ).strip().lower()
        args.deep = answer in ("y", "yes")

    if not any([args.all, args.headers, args.params, args.cloaking,
                args.normalization, args.deception, args.confirm]):
        args.all = True

    try:
        run(args, cfg, deep=args.deep)
    except KeyboardInterrupt:
        console.print("\n[danger]⚠  Interrupted by user.[/danger]")
        sys.exit(130)
    except RuntimeError as exc:
        console.print(f"\n[danger]✖ Aborted:[/danger] [warn]{exc}[/warn]")
        sys.exit(1)


if __name__ == "__main__":
    main()