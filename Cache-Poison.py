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
import asyncio
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse, urljoin, quote

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
    theme=THEME, force_terminal=True, color_system="truecolor",
    legacy_windows=False, highlight=False,
)

CONFIG_FILENAME = "config.json"

PROFILES = {
    "stealth": {
        "rate_limit_per_minute": 30, "min_delay_seconds": 1.2,
        "jitter_max_seconds": 1.5, "batch_size": 8,
        "batch_cooldown_seconds": 6.0, "max_concurrent_probes": 1,
        "concurrency_enabled": False,
    },
    "balanced": {
        "rate_limit_per_minute": 60, "min_delay_seconds": 0.5,
        "jitter_max_seconds": 0.8, "batch_size": 12,
        "batch_cooldown_seconds": 3.0, "max_concurrent_probes": 4,
        "concurrency_enabled": True,
    },
    "fast": {
        "rate_limit_per_minute": 180, "min_delay_seconds": 0.15,
        "jitter_max_seconds": 0.3, "batch_size": 25,
        "batch_cooldown_seconds": 1.0, "max_concurrent_probes": 8,
        "concurrency_enabled": True,
    },
}

DEFAULT_CONFIG = {
    "profile": "balanced",
    "rate_limit_per_minute": 60,
    "min_delay_seconds": 0.5,
    "jitter_max_seconds": 0.8,
    "batch_size": 12,
    "batch_cooldown_seconds": 3.0,
    "timeout_seconds": 12.0,
    "max_requests_per_scan": 700,
    "max_phase_requests": 120,
    "max_consecutive_403": 3,
    "stop_on_403": True,
    "deep_crawl_max_paths": 30,
    "crawl_robots_sitemap": True,
    "crawl_js_bundles": True,
    "verify_cache_double_request": True,
    "verify_cache_wait_seconds": 1.5,
    "poison_settle_seconds": 5.0,
    "confirm_max_reflections": 5,
    "max_concurrent_probes": 4,
    "concurrency_enabled": True,
}

CLOAKING_PARAMS = ["utm_source", "callback", "format", "lang", "debug"]

HPP_DELIMITERS = ["&", ";", "%3B", "%26", "%23", "%3F", "%00", ","]
HPP_POSITIONS = ["before", "after"]

CACHE_KEY_HEADERS = [
    "Accept-Language", "Accept-Encoding", "X-Forwarded-Proto",
    "X-Forwarded-Scheme", "X-HTTP-Method-Override",
    "X-Cache-Key", "X-True-Cache-Key",
]

ESI_PAYLOADS = [
    '<esi:include src="http://{c}/"/>',
    '<esi:vars>$(HTTP_HOST)</esi:vars>',
    '<!--esi <esi:include src="http://{c}/"/> -->',
    '<esi:include src="//{c}/">',
]

BASE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
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


def load_config() -> dict:
    path = Path(CONFIG_FILENAME)
    cfg = dict(DEFAULT_CONFIG)
    if not path.exists():
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(DEFAULT_CONFIG, fh, indent=4)
            console.print(
                f"[info]ℹ Created default config →[/info] "
                f"[bright_white]{CONFIG_FILENAME}[/bright_white]"
            )
        except Exception as exc:
            console.print(f"[warn]⚠ Could not create config: {exc}[/warn]")
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)
        profile = user_cfg.get("profile", "balanced").lower()
        if profile in PROFILES:
            cfg.update(PROFILES[profile])
        for key in DEFAULT_CONFIG:
            if key in user_cfg:
                cfg[key] = user_cfg[key]
        console.print(
            f"[success]✔ Config loaded →[/success] "
            f"[bright_white]{CONFIG_FILENAME}[/bright_white] "
            f"[muted](profile={cfg['profile']}, "
            f"{cfg['rate_limit_per_minute']} req/min)[/muted]"
        )
    except Exception as exc:
        console.print(f"[warn]⚠ Invalid config ({exc}) — using defaults.[/warn]")
    return cfg


def rnd(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def canary_token() -> str:
    return f"{rnd(16)}.invalid"


def cache_buster() -> str:
    return f"_cb={rnd(14)}"


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
    if re.search(rf'href\s*=\s*["\']javascript:[^"\']*{esc}', body, re.I):
        return "javascript-uri"
    if re.search(rf'href\s*=\s*["\']data:[^"\']*{esc}', body, re.I):
        return "data-uri"
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
    if re.search(rf'=\s*{esc}', body, re.I):
        return "unquoted-attr"
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
    verified: bool = False


@dataclass
class Finding:
    phase: str
    kind: str
    severity: str
    input: str
    evidence: str
    context: str = ""
    details: str = ""
    probe_type: str = ""
    probe_key: str = ""
    probe_value: str = ""
    confidence: float = 0.5
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_STYLE = {
    "critical": "critical", "high": "danger", "medium": "warn",
    "low": "info", "info": "muted",
}


class SafetyGuard:
    def __init__(self, cfg: dict):
        self.rate_per_sec = max(cfg["rate_limit_per_minute"] / 60.0, 0.05)
        self.base_delay = max(cfg["min_delay_seconds"], 1.0 / self.rate_per_sec)
        self.jitter_max = float(cfg.get("jitter_max_seconds", 0.0))
        self.batch_size = max(int(cfg.get("batch_size", 999)), 1)
        self.batch_cooldown = float(cfg.get("batch_cooldown_seconds", 0.0))
        self.max_403 = int(cfg.get("max_consecutive_403", 3))
        self.stop_on_403 = bool(cfg.get("stop_on_403", True))

        self.last_request = 0.0
        self.requests_in_batch = 0
        self.consecutive_403 = 0
        self.consecutive_errors = 0
        self.aborted = False
        self.abort_reason = ""
        self._lock = asyncio.Lock()

    def _compute_delay(self) -> float:
        delay = self.base_delay
        if self.jitter_max > 0:
            delay += random.uniform(0, self.jitter_max)
        return delay

    async def before_request(self):
        async with self._lock:
            if self.aborted:
                raise RuntimeError(f"Guard aborted: {self.abort_reason}")

            now = time.time()
            elapsed = now - self.last_request
            target = self._compute_delay()
            if elapsed < target:
                await asyncio.sleep(target - elapsed)

            if self.requests_in_batch >= self.batch_size and self.batch_cooldown > 0:
                console.print(
                    f"  [muted]⏸ batch cooldown {self.batch_cooldown:.1f}s[/muted]"
                )
                await asyncio.sleep(self.batch_cooldown)
                self.requests_in_batch = 0

            self.last_request = time.time()
            self.requests_in_batch += 1

    async def on_response(self, resp):
        if resp is None:
            self.consecutive_errors += 1
            return
        if resp.status_code == 403:
            self.consecutive_403 += 1
            if self.stop_on_403 and self.consecutive_403 >= self.max_403:
                self.aborted = True
                self.abort_reason = (
                    f"{self.consecutive_403} consecutive 403s — target likely "
                    f"blocking. Lower your profile (stealth) and retry."
                )
                console.print(f"  [danger]✖ {self.abort_reason}[/danger]")
        else:
            self.consecutive_403 = 0
            self.consecutive_errors = 0

    def reset_batch(self):
        self.requests_in_batch = 0


class AsyncClient:
    def __init__(self, cfg: dict, proxy: Optional[str], insecure: bool):
        limits = httpx.Limits(
            max_keepalive_connections=cfg["max_concurrent_probes"] * 2,
            max_connections=cfg["max_concurrent_probes"] * 2,
        )
        self.inner = httpx.AsyncClient(
            timeout=cfg["timeout_seconds"],
            follow_redirects=False,
            verify=not insecure,
            proxy=proxy,
            limits=limits,
        )
        self.guard = SafetyGuard(cfg)
        self.request_count = 0
        self.max_requests = cfg["max_requests_per_scan"]
        self.max_phase_requests = cfg["max_phase_requests"]
        self.sem = asyncio.Semaphore(
            cfg["max_concurrent_probes"] if cfg.get("concurrency_enabled") else 1
        )

    async def request(self, method, url, **kwargs):
        if self.request_count >= self.max_requests:
            raise RuntimeError(
                f"Global request cap reached ({self.max_requests}). Aborting."
            )
        async with self.sem:
            await self.guard.before_request()
            headers = kwargs.pop("headers", {})
            merged = {**BASE_HEADERS, **headers}
            for attempt in range(MAX_RETRIES_429 + 1):
                try:
                    resp = await self.inner.request(
                        method, url, headers=merged, **kwargs
                    )
                except httpx.HTTPError as exc:
                    console.print(
                        f"  [danger]✖ request failed:[/danger] [muted]{exc}[/muted]"
                    )
                    await self.guard.on_response(None)
                    if self.guard.consecutive_errors >= 10:
                        raise RuntimeError(
                            "Too many consecutive errors — target may be blocking."
                        )
                    return None
                self.request_count += 1
                await self.guard.on_response(resp)

                if resp.status_code == 429 and attempt < MAX_RETRIES_429:
                    retry_after = int(resp.headers.get("Retry-After", "5"))
                    console.print(
                        f"  [warn]⚠ 429 — sleeping {retry_after}s[/warn]"
                    )
                    await asyncio.sleep(retry_after)
                    continue
                if resp.status_code in (502, 503, 504):
                    await self.guard.on_response(None)
                return resp
            return None

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def close(self):
        await self.inner.aclose()


def header_line(phase: str, title: str):
    console.print()
    console.rule(
        f"[bold magenta]{phase}[/bold magenta] · "
        f"[bold bright_cyan]{title}[/bold bright_cyan]",
        style="bright_magenta", align="left",
    )
    console.print()


def render_banner(cfg: dict, deep: bool):
    mode = "DEEP SCAN" if deep else "NORMAL SCAN"
    mode_color = "bright_red" if deep else "bright_green"
    banner = Text.assemble(
        ("CACHE POISONING & DECEPTION DETECTOR v2.0\n", "bold bright_magenta"),
        ("Mode: ", "dim"), (mode, f"bold {mode_color}"),
        ("   Profile: ", "dim"),
        (cfg.get("profile", "balanced").upper(), "bright_yellow"),
        ("   Rate limit: ", "dim"),
        (f"{cfg['rate_limit_per_minute']} req/min", "bright_cyan"),
        ("\n", ""),
        ("Jitter: ", "dim"),
        (f"{cfg['jitter_max_seconds']}s", "bright_cyan"),
        ("   Batch: ", "dim"),
        (f"{cfg['batch_size']} + {cfg['batch_cooldown_seconds']}s cooldown", "bright_cyan"),
        ("   Concurrency: ", "dim"),
        (f"{cfg['max_concurrent_probes']}", "bright_cyan"),
        ("   Request cap: ", "dim"),
        (f"{cfg['max_requests_per_scan']}", "bright_cyan"),
        ("\n", ""),
    )
    console.print(Panel(
        Align.center(banner),
        border_style="bright_magenta", box=DOUBLE, padding=(1, 4),
    ))
    if cfg.get("profile") == "fast":
        console.print(
            "[warn]⚠ Profile 'fast' — higher ban risk. Use only on targets "
            "you own or have permission to test.[/warn]"
        )


def render_cache_panel(info: CacheInfo, url: str):
    body = Group(
        Text.assemble(("Target     : ", "bold cyan"), (url, "bright_white")),
        Text.assemble(("Cache      : ", "bold cyan"),
                      ("PRESENT" if info.present else "NOT DETECTED",
                       "bright_green" if info.present else "bright_red")),
        Text.assemble(("Verified   : ", "bold cyan"),
                      ("YES (double-request)" if info.verified else "NO",
                       "bright_green" if info.verified else "bright_yellow")),
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


async def detect_cache(client: AsyncClient, url: str, cfg: dict) -> CacheInfo:
    header_line("PHASE 1", "Cache Layer Detection & Verification")
    info = CacheInfo()
    buster = cache_buster()
    test_url = add_query(url, buster)

    r1 = await client.get(test_url)
    if not r1:
        console.print("[danger]✖ Unable to reach target.[/danger]")
        return info

    for h in CACHE_HEADERS_OF_INTEREST:
        if h in r1.headers:
            info.headers[h] = r1.headers[h]

    info.provider = detect_cdn_provider(r1.headers, r1.text)

    try:
        if int(r1.headers.get("age", "0")) > 0:
            info.present = True
            info.verified = True
    except ValueError:
        pass

    if "cache-control" in r1.headers:
        info.ttl_hint = r1.headers["cache-control"]

    s1 = classify_cache_status(r1.headers)
    if s1 == "hit":
        info.present = True
        info.verified = True

    if cfg.get("verify_cache_double_request") and not info.verified:
        await asyncio.sleep(cfg.get("verify_cache_wait_seconds", 1.5))
        r2 = await client.get(test_url)
        if r2:
            s2 = classify_cache_status(r2.headers)
            if s1 == "miss" and s2 == "hit":
                info.present = True
                info.verified = True
                console.print("  [success]✔ Cache verified (MISS → HIT)[/success]")
            elif s1 == "unknown" and s2 == "hit":
                info.present = True
                info.verified = True
                console.print("  [success]✔ Cache verified (HIT on 2nd request)[/success]")
            elif s2 == "hit":
                info.present = True
                info.verified = True

    trusted = {"x-cache", "cf-cache-status", "x-cache-status", "x-cache-lookup",
               "eo-cache-status", "x-vercel-cache", "x-served-by"}
    if not info.verified and any(h in info.headers for h in trusted):
        info.present = True

    render_cache_panel(info, url)
    return info


async def detect_spa(client: AsyncClient, url: str) -> bool:
    base = await client.get(url)
    if not base:
        return False
    hashes = set()
    for _ in range(3):
        resp = await client.get(replace_path(url, "/" + rnd(16)))
        if not resp:
            continue
        hashes.add((resp.status_code, short_hash(resp.content)))
    if not hashes:
        return False
    base_key = (base.status_code, short_hash(base.content))
    return base_key in hashes


async def crawl_static_paths(client: AsyncClient, base_url: str,
                              cfg: dict) -> list[str]:
    header_line("CRAWL", "Path Discovery")
    discovered: list[str] = []
    seen_paths: set[str] = set()
    base_host = urlparse(base_url).netloc
    scheme = urlparse(base_url).scheme

    def add_path(path: str):
        if not path or path == "/":
            return
        is_static_ext = any(path.lower().endswith(ext) for ext in STATIC_EXTENSIONS)
        is_static_dir = any(d in path.lower() for d in STATIC_DIRECTORIES)
        if not (is_static_ext or is_static_dir):
            return
        if path in seen_paths:
            return
        seen_paths.add(path)
        discovered.append(f"{scheme}://{base_host}{path}")

    resp = await client.get(base_url)
    if resp:
        links = re.findall(
            r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', resp.text, re.I
        )
        for link in links:
            link = link.strip()
            if not link or link.startswith(("javascript:", "mailto:", "data:", "#")):
                continue
            absolute = urljoin(base_url, link)
            parsed = urlparse(absolute)
            if parsed.netloc != base_host:
                continue
            add_path(parsed.path)

    if cfg.get("crawl_robots_sitemap"):
        rb = await client.get(f"{scheme}://{base_host}/robots.txt")
        if rb and rb.status_code == 200:
            for line in rb.text.splitlines():
                m = re.match(r"(?:Disallow|Allow):\s*(\S+)", line.strip(), re.I)
                if m:
                    add_path(urlparse(m.group(1)).path)
            for line in rb.text.splitlines():
                m = re.match(r"Sitemap:\s*(\S+)", line.strip(), re.I)
                if m:
                    sm = await client.get(m.group(1))
                    if sm:
                        for loc in re.findall(r"<loc>([^<]+)</loc>", sm.text):
                            parsed = urlparse(loc.strip())
                            if parsed.netloc == base_host:
                                add_path(parsed.path)

        sm = await client.get(f"{scheme}://{base_host}/sitemap.xml")
        if sm and sm.status_code == 200:
            for loc in re.findall(r"<loc>([^<]+)</loc>", sm.text):
                parsed = urlparse(loc.strip())
                if parsed.netloc == base_host:
                    add_path(parsed.path)

    if cfg.get("crawl_js_bundles") and resp:
        js_urls = re.findall(
            r'src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', resp.text, re.I
        )
        for js in js_urls[:10]:
            absolute = urljoin(base_url, js)
            if urlparse(absolute).netloc != base_host:
                continue
            jsr = await client.get(absolute)
            if not jsr:
                continue
            for m in re.findall(r'["\']([^"\']+\.map)["\']', jsr.text):
                add_path(urlparse(urljoin(absolute, m)).path)

    limit = cfg.get("deep_crawl_max_paths", 30)
    discovered = discovered[:limit]

    if not discovered:
        console.print("[muted]◦ No static paths found.[/muted]")
    else:
        console.print(f"[info]▸ Discovered {len(discovered)} path(s):[/info]")
        for p in discovered:
            console.print(f"  [cyan]→[/cyan] {truncate(p, 90)}")
    return discovered


async def phase_header_reflection(client: AsyncClient, url: str,
                                   cfg: dict) -> list[Finding]:
    header_line("PHASE 2", "Unkeyed Header Reflection")
    findings = []
    base = await client.get(add_query(url, cache_buster()))
    if not base:
        return findings
    base_len = len(base.content)
    cap = cfg.get("max_phase_requests", 120)
    done = 0

    for h in UNKEYED_HEADERS:
        if done >= cap:
            console.print(f"  [muted]◦ phase cap reached ({cap})[/muted]")
            break
        canary = canary_token()
        resp = await client.get(add_query(url, cache_buster()), headers={h: canary})
        done += 1
        if not resp:
            continue
        if canary in resp.text:
            ctx = detect_html_context(resp.text, canary)
            sev = "high" if ctx not in ("body",) else "medium"
            conf = 0.9 if ctx in ("script-body", "javascript-uri") else 0.6
            findings.append(Finding(
                phase="Header Reflection", kind="reflection",
                severity=sev, input=f"{h} @ {urlparse(url).path or '/'}",
                evidence=f"Canary reflected ({ctx})",
                context=ctx,
                details=f"Δlen={len(resp.content) - base_len:+d}B",
                probe_type="header", probe_key=h, probe_value=canary,
                confidence=conf,
                remediation=(
                    "Do not reflect unkeyed request headers into response body. "
                    "Normalize/whitelist X-Forwarded-* at the cache layer."
                ),
            ))
            console.print(f"  [warn]⚠[/warn] [cyan]{h}[/cyan] → [warn]{ctx}[/warn]")
        for rk, rv in resp.headers.items():
            if canary in rv:
                findings.append(Finding(
                    phase="Header Reflection", kind="reflection",
                    severity="medium",
                    input=f"{h} @ {urlparse(url).path or '/'}",
                    evidence=f"Reflected in response header '{rk}'",
                    context="response-header",
                    details=f"value={truncate(rv, 60)}",
                    probe_type="header", probe_key=h, probe_value=canary,
                    confidence=0.5,
                    remediation="Do not echo request headers into response headers.",
                ))
                break
    return findings


async def phase_param_reflection(client: AsyncClient, url: str,
                                  cfg: dict) -> list[Finding]:
    header_line("PHASE 3", "Unkeyed Query-Parameter Reflection")
    findings = []
    base = await client.get(add_query(url, cache_buster()))
    if not base:
        return findings
    base_len = len(base.content)
    cap = cfg.get("max_phase_requests", 120)

    for p in UNKEYED_PARAMS[:cap]:
        canary = canary_token()
        resp = await client.get(add_query(url, f"{p}={quote(canary)}&{cache_buster()}"))
        if not resp:
            continue
        if canary in resp.text:
            ctx = detect_html_context(resp.text, canary)
            sev = "high" if ctx != "body" else "medium"
            conf = 0.9 if ctx in ("script-body", "javascript-uri") else 0.6
            findings.append(Finding(
                phase="Parameter Reflection", kind="reflection",
                severity=sev, input=f"?{p}= @ {urlparse(url).path or '/'}",
                evidence=f"Canary reflected ({ctx})",
                context=ctx,
                details=f"Δlen={len(resp.content) - base_len:+d}B",
                probe_type="query", probe_key=p, probe_value=canary,
                confidence=conf,
                remediation=(
                    "Do not reflect unkeyed query parameters. If user-controlled, "
                    "encode and make the parameter part of the cache key."
                ),
            ))
            console.print(f"  [warn]⚠[/warn] [cyan]?{p}=[/cyan] → [warn]{ctx}[/warn]")
    return findings


async def phase_param_cloaking(client: AsyncClient, url: str,
                                cfg: dict) -> list[Finding]:
    header_line("PHASE 4", "HPP & Parameter Cloaking Matrix")
    findings = []
    base = await client.get(add_query(url, cache_buster()))
    if not base:
        return findings
    base_len = len(base.content)
    cap = cfg.get("max_phase_requests", 120)
    done = 0

    for p in CLOAKING_PARAMS:
        if done >= cap:
            console.print(f"  [muted]◦ phase cap reached ({cap})[/muted]")
            break
        malicious = f"POISON-{rnd(6)}"
        for delim in HPP_DELIMITERS:
            for pos in HPP_POSITIONS:
                if done >= cap:
                    break
                if pos == "before":
                    payload = f"{p}={malicious}{delim}{p}=benign"
                else:
                    payload = f"{p}=benign{delim}{p}={malicious}"
                resp = await client.get(add_query(url, f"{payload}&{cache_buster()}"))
                done += 1
                if not resp:
                    continue
                if malicious in resp.text:
                    findings.append(Finding(
                        phase="Parameter Cloaking", kind="cloaking",
                        severity="high",
                        input=f"?{p}= ({pos} {delim}) @ "
                              f"{urlparse(url).path or '/'}",
                        evidence=(
                            "Origin used the malicious duplicate value while "
                            "cache keyed on the benign one"
                        ),
                        context=f"delim={delim} pos={pos}",
                        details=f"Δlen={len(resp.content) - base_len:+d}B",
                        probe_type="query", probe_key=p,
                        probe_value=malicious,
                        confidence=0.85,
                        remediation=(
                            "Ensure origin and cache interpret duplicate "
                            "parameters identically. Reject HPP payloads."
                        ),
                    ))
                    console.print(
                        f"  [warn]⚠[/warn] [cyan]{p}[/cyan] via "
                        f"[magenta]{delim}[/magenta] ({pos})"
                    )
                    break
            else:
                continue
            break
    return findings


async def phase_normalization(client: AsyncClient, url: str,
                                cfg: dict) -> list[Finding]:
    header_line("PHASE 5", "Cache-Key Normalization")
    findings = []
    base_resp = await client.get(add_query(url, cache_buster()))
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
        (base_path.replace("/", "\\"), "backslash"),
        (base_path + "%2f", "encoded-slash"),
        (base_path + "/%2e", "encoded-dot"),
    ]
    q_base = urlparse(add_query(url, cache_buster()))
    query_variants = []
    if "?" in url or q_base.query:
        query_variants.append(
            (q_base._replace(query=q_base.query.upper()).geturl(),
             "query-uppercase")
        )

    cap = cfg.get("max_phase_requests", 120)
    done = 0
    for variant_path, label in variants:
        if done >= cap:
            break
        resp = await client.get(replace_path(add_query(url, cache_buster()),
                                              variant_path))
        done += 1
        if not resp:
            continue
        if short_hash(resp.content) == base_hash and resp.status_code == 200:
            findings.append(Finding(
                phase="Normalization", kind="normalization",
                severity="medium",
                input=f"{variant_path} @ {base_path}",
                evidence=f"Variant '{label}' returned identical body",
                context="cache-key-collision",
                details=f"status={resp.status_code} | hash={short_hash(resp.content)}",
                probe_type="path", probe_key=label, probe_value=variant_path,
                confidence=0.5,
                remediation=(
                    "Normalize cache key consistently across CDN and origin. "
                    "Reject non-canonical paths."
                ),
            ))
            console.print(f"  [warn]⚠[/warn] normalization: [cyan]{label}[/cyan]")

    for variant_url, label in query_variants:
        if done >= cap:
            break
        resp = await client.get(variant_url)
        done += 1
        if resp and short_hash(resp.content) == base_hash:
            findings.append(Finding(
                phase="Normalization", kind="normalization",
                severity="low",
                input=f"{label}",
                evidence="Query-case variant produced identical body",
                context="query-case",
                details=f"status={resp.status_code}",
                probe_type="query", probe_key=label, probe_value=variant_url,
                confidence=0.3,
                remediation="Treat query param case consistently.",
            ))
    return findings


DECEPTION_EXTENSIONS = STATIC_EXTENSIONS + [
    ".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".rss", ".pdf",
]


async def phase_cache_deception(client: AsyncClient, url: str,
                                 cfg: dict) -> list[Finding]:
    header_line("PHASE 6", "Web Cache Deception (expanded)")
    findings = []
    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/") or "/"
    cap = cfg.get("max_phase_requests", 120)
    done = 0

    def _test(payload_path, label):
        return replace_path(add_query(url, cache_buster()), payload_path)

    for ext in DECEPTION_EXTENSIONS:
        if done >= cap:
            break
        resp = await client.get(_test(f"{base_path}{ext}", f"ext{ext}"))
        done += 1
        if not resp:
            continue
        if (classify_cache_status(resp.headers) == "hit"
                and "text/html" in resp.headers.get("content-type", "").lower()
                and resp.status_code == 200):
            findings.append(Finding(
                phase="Cache Deception", kind="deception",
                severity="high", input=f"{base_path}{ext}",
                evidence="Static-suffixed path cached, serves dynamic HTML",
                context=f"cache=hit | path={base_path}",
                details=f"status={resp.status_code} | ext={ext}",
                probe_type="path", probe_key=ext, probe_value=f"{base_path}{ext}",
                confidence=0.8,
                remediation=(
                    "Do not cache responses based on URL extension alone. "
                    "Respect origin Content-Type and Cache-Control."
                ),
            ))
            console.print(f"  [warn]⚠[/warn] deception via [magenta]{ext}[/magenta]")

    for d in DELIMITERS:
        if done >= cap:
            break
        resp = await client.get(_test(f"{base_path}{d}deception.css", "delim"))
        done += 1
        if not resp:
            continue
        if (classify_cache_status(resp.headers) == "hit"
                and "text/html" in resp.headers.get("content-type", "").lower()):
            findings.append(Finding(
                phase="Cache Deception", kind="deception",
                severity="high", input=f"{base_path}{d}…",
                evidence=f"Delimiter '{d}' confused the cache",
                context="delimiter-confusion",
                details=f"status={resp.status_code}",
                probe_type="path", probe_key=d,
                probe_value=f"{base_path}{d}deception.css",
                confidence=0.8,
                remediation="Reject paths with encoded delimiters.",
            ))
            console.print(f"  [warn]⚠[/warn] deception via [magenta]{d}[/magenta]")
            break

    for ext in (".css.php", ".css.json", ".html.php"):
        if done >= cap:
            break
        resp = await client.get(_test(f"{base_path}{ext}", "double-ext"))
        done += 1
        if resp and classify_cache_status(resp.headers) == "hit":
            findings.append(Finding(
                phase="Cache Deception", kind="deception",
                severity="medium", input=f"{base_path}{ext}",
                evidence="Double-extension cached",
                context="double-extension",
                details=f"status={resp.status_code}",
                probe_type="path", probe_key=ext,
                probe_value=f"{base_path}{ext}",
                confidence=0.5,
                remediation="Do not cache based on trailing extension only.",
            ))
    return findings


async def phase_esi_injection(client: AsyncClient, url: str,
                                cfg: dict) -> list[Finding]:
    header_line("PHASE 6b", "ESI Injection")
    findings = []
    cap = cfg.get("max_phase_requests", 120)
    done = 0

    for payload in ESI_PAYLOADS:
        if done >= cap:
            break
        canary = canary_token()
        filled = payload.format(c=canary)
        for probe_type, kwargs, key in (
            ("header", {"headers": {"X-Forwarded-Host": filled}}, "X-Forwarded-Host"),
            ("query", None, "esi"),
        ):
            if done >= cap:
                break
            if probe_type == "header":
                resp = await client.get(add_query(url, cache_buster()), **kwargs)
            else:
                resp = await client.get(
                    add_query(url, f"esi={quote(filled)}&{cache_buster()}")
                )
            done += 1
            if not resp:
                continue
            if filled in resp.text:
                findings.append(Finding(
                    phase="ESI Injection", kind="esi",
                    severity="high",
                    input=f"{probe_type}:{key}",
                    evidence="ESI tag reflected unescaped — possible evaluation",
                    context="esi-reflection",
                    details=f"payload={truncate(filled, 60)}",
                    probe_type=probe_type, probe_key=key, probe_value=filled,
                    confidence=0.6,
                    remediation=(
                        "Disable ESI for untrusted input, or strip ESI tags "
                        "before caching."
                    ),
                ))
                console.print(
                    f"  [warn]⚠[/warn] ESI reflected via [cyan]{probe_type}:{key}[/cyan]"
                )
                break
    return findings


async def phase_host_poison(client: AsyncClient, url: str,
                             cfg: dict) -> list[Finding]:
    header_line("PHASE 6c", "Host Header Poisoning")
    findings = []
    canary = canary_token()
    resp = await client.get(add_query(url, cache_buster()),
                             headers={"Host": canary})
    if not resp:
        return findings

    if canary in resp.text:
        ctx = detect_html_context(resp.text, canary)
        findings.append(Finding(
            phase="Host Poisoning", kind="host-poison",
            severity="critical" if ctx != "body" else "high",
            input=f"Host: {canary}",
            evidence=f"Host reflected in HTML ({ctx}) — absolute URLs poisoned",
            context=ctx,
            details=f"status={resp.status_code}",
            probe_type="header", probe_key="Host", probe_value=canary,
            confidence=0.85,
            remediation=(
                "Validate Host header against allow-list. Never use it to "
                "build absolute URLs returned to clients."
            ),
        ))
        console.print(f"  [warn]⚠[/warn] Host reflected → [warn]{ctx}[/warn]")

    for h in ("X-Forwarded-Host", "X-Host", "X-Original-Host"):
        canary2 = canary_token()
        r = await client.get(add_query(url, cache_buster()), headers={h: canary2})
        if not r:
            continue
        if re.search(rf'href=["\']https?://{re.escape(canary2)}', r.text):
            findings.append(Finding(
                phase="Host Poisoning", kind="host-poison",
                severity="critical",
                input=f"{h}: {canary2}",
                evidence="Absolute URL in HTML uses attacker-controlled host",
                context="absolute-url-poison",
                details="href=... canary ...",
                probe_type="header", probe_key=h, probe_value=canary2,
                confidence=0.9,
                remediation="Never build absolute URLs from X-Forwarded-Host.",
            ))
            console.print(f"  [danger]⚠[/danger] {h} → absolute URL poison")
            break
    return findings


async def phase_cache_key_injection(client: AsyncClient, url: str,
                                     cfg: dict) -> list[Finding]:
    header_line("PHASE 6d", "Cache-Key Injection (Accept-*, X-Cache-Key)")
    findings = []
    cap = cfg.get("max_phase_requests", 120)
    done = 0

    for h in CACHE_KEY_HEADERS:
        if done >= cap:
            break
        canary = rnd(12)
        resp = await client.get(
            add_query(url, cache_buster()), headers={h: canary}
        )
        done += 1
        if not resp:
            continue
        if canary in resp.text:
            findings.append(Finding(
                phase="Cache-Key Injection", kind="cache-key",
                severity="medium",
                input=f"{h}: {canary}",
                evidence="Header value reflected in body",
                context="header-reflection",
                details=f"status={resp.status_code}",
                probe_type="header", probe_key=h, probe_value=canary,
                confidence=0.5,
                remediation="Do not reflect Accept-* / X-Cache-* headers.",
            ))
        if h in ("X-Cache-Key", "X-True-Cache-Key") and resp.status_code == 200:
            if classify_cache_status(resp.headers) == "hit":
                findings.append(Finding(
                    phase="Cache-Key Injection", kind="cache-key",
                    severity="critical",
                    input=f"{h}: {canary}",
                    evidence="CDN honored cache-key override header",
                    context="cache-key-override",
                    details=f"status={resp.status_code}",
                    probe_type="header", probe_key=h, probe_value=canary,
                    confidence=0.9,
                    remediation=(
                        "Strip X-Cache-Key / X-True-Cache-Key from inbound "
                        "requests at the edge."
                    ),
                ))
                console.print(
                    f"  [danger]⚠[/danger] {h} honored → [critical]cache-key override[/critical]"
                )
    return findings


async def phase_fat_get(client: AsyncClient, url: str,
                         cfg: dict) -> list[Finding]:
    header_line("PHASE 6e", "Fat GET (body on GET)")
    findings = []
    canary = canary_token()
    resp = await client.request(
        "GET", add_query(url, cache_buster()),
        content=f"fatget={canary}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp and canary in resp.text:
        findings.append(Finding(
            phase="Fat GET", kind="fat-get",
            severity="high",
            input="GET body parameter",
            evidence="Origin used GET body while cache cannot key on it",
            context="fat-get",
            details=f"status={resp.status_code}",
            probe_type="body", probe_key="fatget", probe_value=canary,
            confidence=0.7,
            remediation="Reject GET requests with a body at the edge.",
        ))
        console.print("  [warn]⚠[/warn] Fat GET body reflected")
    return findings


async def phase_poison_confirm(client: AsyncClient, url: str,
                                 findings: list[Finding],
                                 cfg: dict) -> list[Finding]:
    header_line("PHASE 7", "Poison Confirmation")
    confirmations = []
    high = [f for f in findings
            if f.kind in ("reflection", "cloaking", "host-poison", "esi")
            and f.severity in ("high", "critical")]
    if not high:
        console.print("[muted]No high-severity reflections — skipping.[/muted]")
        return confirmations

    max_confirm = cfg.get("confirm_max_reflections", 5)
    settle = cfg.get("poison_settle_seconds", 5.0)

    for f in high[:max_confirm]:
        canary = f"POISON-{rnd(6)}.invalid"
        buster = cache_buster()
        poison_url = add_query(url, buster)
        headers = {}

        if f.probe_type == "header":
            headers[f.probe_key] = canary
        elif f.probe_type == "query":
            poison_url = add_query(url, f"{f.probe_key}={quote(canary)}&{buster}")
        elif f.probe_type == "path":
            continue
        else:
            continue

        r1 = await client.get(poison_url, headers=headers)
        if not r1 or canary not in r1.text:
            console.print(f"  [muted]◦ {f.probe_key}: not reflected, skip[/muted]")
            continue

        await asyncio.sleep(settle)
        r2 = await client.get(poison_url, headers=headers)
        persisted = r2 is not None and canary in r2.text

        r3 = await client.get(add_query(url, cache_buster()))
        leaked = r3 is not None and canary in r3.text

        if persisted and not leaked:
            confirmations.append(Finding(
                phase="Poison Confirmation", kind="poison_confirm",
                severity="critical",
                input=f.input,
                evidence="Poison persisted in cache under its buster",
                context=f"cache={classify_cache_status(r2.headers)}",
                details=f"canary={canary} | isolated=True",
                probe_type=f.probe_type, probe_key=f.probe_key,
                probe_value=canary, confidence=0.95,
                remediation=(
                    "Confirm the poisoned URL is served to real users. Purge "
                    "cache immediately and fix the unkeyed input."
                ),
            ))
            console.print(f"  [danger]✔[/danger] {f.probe_key}: confirmed")
        elif persisted and leaked:
            confirmations.append(Finding(
                phase="Poison Confirmation", kind="poison_confirm",
                severity="critical", input=f.input,
                evidence="Poison leaked to fresh buster — broad impact",
                context="cache-wide",
                details=f"canary={canary} | isolated=False",
                probe_type=f.probe_type, probe_key=f.probe_key,
                probe_value=canary, confidence=1.0,
                remediation="CRITICAL: purge cache and fix immediately.",
            ))
            console.print(
                f"  [danger]✔[/danger] {f.probe_key}: escaped isolation (critical)"
            )
        else:
            console.print(f"  [muted]◦ {f.probe_key}: did not persist[/muted]")
    return confirmations


async def scan_single_path(client: AsyncClient, path_url: str,
                             args, cfg: dict,
                             include_spa_check: bool = True):
    findings = []
    cache_info = await detect_cache(client, path_url, cfg)

    if not cache_info.present:
        console.print(
            f"[muted]◦ No cache on {urlparse(path_url).path} — skipping.[/muted]"
        )
        return findings, cache_info

    is_spa = False
    if include_spa_check:
        is_spa = await detect_spa(client, path_url)
        if is_spa:
            console.print("[warn]⚠ SPA — normalization may false-positive.[/warn]")

    client.guard.reset_batch()

    if args.headers or args.all:
        findings.extend(await phase_header_reflection(client, path_url, cfg))
    if args.params or args.all:
        findings.extend(await phase_param_reflection(client, path_url, cfg))
    if args.all or args.cloaking:
        findings.extend(await phase_param_cloaking(client, path_url, cfg))
    if (args.all or args.normalization) and not is_spa:
        findings.extend(await phase_normalization(client, path_url, cfg))
    if args.all or args.deception:
        findings.extend(await phase_cache_deception(client, path_url, cfg))
    if args.all or args.esi:
        findings.extend(await phase_esi_injection(client, path_url, cfg))
    if args.all or args.host:
        findings.extend(await phase_host_poison(client, path_url, cfg))
    if args.all or args.cachekey:
        findings.extend(await phase_cache_key_injection(client, path_url, cfg))
    if args.all or args.fatget:
        findings.extend(await phase_fat_get(client, path_url, cfg))
    if args.confirm or args.all:
        findings.extend(await phase_poison_confirm(client, path_url, findings, cfg))

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

    findings_sorted = sorted(
        findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), -f.confidence)
    )
    tbl = Table(
        title="[bold bright_magenta]✦ FINDINGS ✦[/bold bright_magenta]",
        border_style="bright_cyan", box=ROUNDED,
        show_lines=True, padding=(0, 1), expand=False,
    )
    tbl.add_column("#", style="dim", width=4, justify="right")
    tbl.add_column("Sev", width=10, justify="center")
    tbl.add_column("Kind", style="bold cyan", width=18)
    tbl.add_column("Input", style="bright_yellow", width=32)
    tbl.add_column("Evidence", style="bright_white", width=46)
    tbl.add_column("Conf", width=6, justify="center")
    for i, f in enumerate(findings_sorted, 1):
        style = SEV_STYLE.get(f.severity, "white")
        tbl.add_row(
            str(i), Text(f.severity.upper(), style=style), f.kind,
            truncate(f.input, 32), f.evidence, f"{f.confidence:.2f}",
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
            "No verified cache layer on any tested path.\n"
            "Cache poisoning/deception not applicable.",
            "info",
        )
    elif any(f.severity == "critical" for f in findings):
        icon, desc, style = (
            "🔥  CRITICAL",
            "Cache poisoning confirmed on at least one path.",
            "critical",
        )
    elif any(f.severity == "high" for f in findings):
        icon, desc, style = (
            "⚡  HIGH",
            "High-severity indicators (reflection/deception).",
            "danger",
        )
    elif any(f.severity == "medium" for f in findings):
        icon, desc, style = (
            "⚠  MEDIUM",
            "Moderate indicators found.",
            "warn",
        )
    elif findings:
        icon, desc, style = ("ℹ  INFO", "Low-signal findings only.", "info")
    else:
        icon, desc, style = ("🛡  CLEAN", "No indicators.", "success")
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
        "version": "2.0",
        "mode": "deep" if deep else "normal",
        "profile": cfg.get("profile"),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": url,
        "config": cfg,
        "paths_scanned": [
            {
                "url": u, "cache_present": ci.present, "verified": ci.verified,
                "provider": ci.provider, "ttl_hint": ci.ttl_hint,
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
            f"**Version:** {payload['version']}  ",
            f"**Mode:** {payload['mode']}  ",
            f"**Profile:** {payload['profile']}  ",
            f"**Generated:** {payload['timestamp']}  ",
            f"**Paths scanned:** {len(cache_infos)}  ",
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
                f"- `{u}` — present={ci.present}, verified={ci.verified}, "
                f"provider={ci.provider}"
            )
        lines += ["", "## Findings", ""]
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. [{f.severity.upper()}] {f.kind} — {f.input}")
            lines.append("")
            lines.append(f"- **Evidence:** {f.evidence}")
            lines.append(f"- **Context:** {f.context or '—'}")
            lines.append(f"- **Details:** {f.details or '—'}")
            lines.append(f"- **Confidence:** {f.confidence}")
            lines.append(f"- **Remediation:** {f.remediation or '—'}")
            lines.append(f"- **Timestamp:** {f.timestamp}")
            lines.append("")
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    return filename


async def run_async(args, cfg, deep):
    render_banner(cfg, deep)
    client = AsyncClient(cfg, proxy=args.proxy, insecure=args.insecure)

    all_findings: list[Finding] = []
    cache_infos: dict[str, CacheInfo] = {}

    try:
        base_findings, base_cache = await scan_single_path(
            client, args.url, args, cfg, include_spa_check=True
        )
        all_findings.extend(base_findings)
        cache_infos[args.url] = base_cache

        if not deep:
            if not base_cache.present:
                console.print()
                console.print(Panel(
                    Text.assemble(
                        ("No cache layer detected on this target.\n\n",
                         "bold bright_yellow"),
                        ("Cache poisoning/deception not applicable.\n", "dim white"),
                        ("Tip: enable Deep Scan to test static paths.", "muted"),
                    ),
                    title="[bold bright_yellow]⊘  SCAN TERMINATED[/bold bright_yellow]",
                    border_style="bright_yellow", box=HEAVY, padding=(1, 3),
                ))
            render_findings(all_findings)
            render_verdict(all_findings,
                           cache_present=any(ci.present for ci in cache_infos.values()))
            if args.export:
                path = export_report(all_findings, cache_infos, args.url,
                                     args.export, cfg, deep)
                console.print(f"[success]✔ Report →[/success] [info]{path}[/info]\n")
            return all_findings

        paths = await crawl_static_paths(client, args.url, cfg)

        if not paths:
            console.print("[warn]⚠ No static paths — base results only.[/warn]")
        else:
            for i, path_url in enumerate(paths, 1):
                console.print()
                console.print(
                    f"[bold magenta]═══ Path {i}/{len(paths)} ═══[/bold magenta] "
                    f"[bright_cyan]{truncate(path_url, 80)}[/bright_cyan]"
                )
                try:
                    path_findings, path_cache = await scan_single_path(
                        client, path_url, args, cfg, include_spa_check=False
                    )
                    all_findings.extend(path_findings)
                    cache_infos[path_url] = path_cache
                except RuntimeError as exc:
                    console.print(f"[danger]✖ Stopped on path: {exc}[/danger]")
                    break

    finally:
        await client.close()

    render_findings(all_findings)
    render_verdict(all_findings,
                   cache_present=any(ci.present for ci in cache_infos.values()))
    if args.export:
        path = export_report(all_findings, cache_infos, args.url,
                             args.export, cfg, deep)
        console.print(f"[success]✔ Report →[/success] [info]{path}[/info]\n")
    return all_findings


def run(args, cfg, deep):
    return asyncio.run(run_async(args, cfg, deep))


def main():
    parser = argparse.ArgumentParser(
        prog="cache_poison_detector",
        description="Cache Poisoning & Deception Detector v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles (in config.json):
  stealth   - 30 req/min, heavy jitter, no concurrency   (safest)
  balanced  - 60 req/min, moderate jitter, concurrency 4 (default)
  fast      - 180 req/min, concurrency 8                 (ban risk!)
""",
    )
    parser.add_argument("--url")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--params", action="store_true")
    parser.add_argument("--cloaking", action="store_true")
    parser.add_argument("--normalization", action="store_true")
    parser.add_argument("--deception", action="store_true")
    parser.add_argument("--esi", action="store_true")
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--cachekey", action="store_true")
    parser.add_argument("--fatget", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--deep", action="store_true")
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
            "[cyan]▶ Enable Deep Scan? [y/N]: [/cyan]"
        ).strip().lower()
        args.deep = answer in ("y", "yes")

    if not any([args.all, args.headers, args.params, args.cloaking,
                args.normalization, args.deception, args.esi,
                args.host, args.cachekey, args.fatget, args.confirm]):
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
