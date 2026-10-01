# LeakRadar

**Point it at a domain. It tells you what's leaking.**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![HIBP](https://img.shields.io/badge/HIBP-integrated-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

LeakRadar is a domain-focused breach and secret exposure scanner. Give it a target domain — it queries HaveIBeenPwned for breached accounts, runs Google dorks for exposed pastes and configs, greps GitHub and GitLab for leaked keys, and returns a single consolidated report.

---

## Why this exists

Bug-bounty triage, blue-team recon, and pre-engagement scoping all start the same way — you type a domain into six different tools and stitch the answers together. LeakRadar is that stitching, made into one FastAPI endpoint plus a static frontend. No accounts, no dashboards to configure, no telemetry — you bring your own API keys (or run key-less against public sources).

---

## Try it in 60 seconds

```bash
git clone https://github.com/Danush-Aries/leakradar
cd leakradar
pip install -r requirements.txt
python run.py
```

Then open http://localhost:8765, enter a domain, optionally paste your HIBP / SerpAPI / GitHub tokens, and hit search.

```bash
# Or hit the API directly (API keys are optional query params: hibp_key, serp_key, github_token, gitlab_token, bd_key)
curl "http://localhost:8765/api/search?domain=example.com"
curl "http://localhost:8765/api/dorks?domain=example.com"   # generated Google dork queries
```

---

## How it works

```
domain
  |
  v
+------------------------ Searcher ------------------------+
|                                                          |
|  hibp.py         -> HaveIBeenPwned breach lookup         |
|  dork_search.py  -> Google dorks (SerpAPI)               |
|  github_search.py-> GitHub secret grep (per-file scan)   |
|  code_search.py  -> GitLab code search                   |
|  paste_search.py -> Pastebin / paste-site mirrors        |
|                                                          |
+---------------------------|------------------------------+
                            v
              consolidated JSON report
                     (severity-sorted + summary)
                            v
              FastAPI /api/search + web UI
```

Each source is an isolated module under `backend/sources/` so adding a new leak feed is a single-file change.

---

## Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI + Uvicorn |
| Sources | HIBP API, SerpAPI, GitHub Code Search, GitLab, paste mirrors |
| Frontend | Vanilla JS + HTML (zero build step) |
| Config | Per-request API keys, no persistent storage |

---

## More from Danush

Part of a broader stack of AI + security tooling:

- [jarvis](https://github.com/Danush-Aries/jarvis) — portable multi-provider AI assistant (voice/web/CLI)
- [breachintel](https://github.com/Danush-Aries/breachintel) — OSINT breach intelligence aggregator
- [cve-advisor](https://github.com/Danush-Aries/cve-advisor) — AI-powered CVE triage and patch recommendation
- [llm-fragility-lab](https://github.com/Danush-Aries/llm-fragility-lab) — adversarial testing lab for LLM robustness
- [network-intrusion-analyzer](https://github.com/Danush-Aries/network-intrusion-analyzer) — Suricata + Claude AI intrusion triage
- [autonomous-coding-agent](https://github.com/Danush-Aries/autonomous-coding-agent) — two-agent autonomous coding system

Built by [Dhanush](https://github.com/Danush-Aries) — AI engineering + cybersecurity.

## License

MIT — see [LICENSE](LICENSE).

Use only against domains you own or are authorised to assess.
