# Cache-Poison

A security tool that detects **web cache** vulnerabilities in web applications.

## What it detects

- **Cache Poisoning** — poisoning the cached response so it reaches every visitor.
- **Cache Deception** — tricking the CDN into caching dynamic, sensitive pages.
- **Parameter Cloaking** — exploiting parsing mismatches between CDN and origin.
- **Cache-Key Normalization** — exploiting path-normalization differences between layers.

## Why it's safe

- Every request carries a **unique cache buster** (`_cb=...`) — shared entries are never touched.
- **Adaptive rate limiting** automatically backs off on 429 and 502/503 responses.
- **Early exit** when no cache layer is detected — no wasted requests.
- **Request cap** per scan, configurable via `config.json`.

## How it works

1. **Normal Scan** — tests only the supplied URL. If no cache is found, it stops immediately.
2. **Deep Scan** — crawls the page, extracts static paths (`.css`, `.js`, `/static/`, `/assets/`...), and tests each one.

## Requirements

- Python 3.10+
- `httpx`, `rich`

## Disclaimer
This tool is created for educational purposes, authorized security assessments, and Bug Bounty programs only.
The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
Use responsibly and only on targets you have explicit permission to test.
