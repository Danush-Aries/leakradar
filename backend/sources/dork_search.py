"""
Dork-based search via DuckDuckGo HTML, SerpAPI (optional), and Google CSE (optional).
Also generates the dork query list for manual searching.
"""
import httpx
import re
from typing import Optional
from bs4 import BeautifulSoup


DORK_TEMPLATES = [
    'site:pastebin.com "@{domain}"',
    'site:github.com "@{domain}" password',
    '"@{domain}" "password" filetype:txt',
    '"@{domain}" "password" filetype:csv',
    'site:trello.com "@{domain}" password OR secret',
    '"{domain}" "leaked" OR "breach" OR "dump" -site:{domain}',
    'site:raidforums.com OR site:breachforums.com "{domain}"',
    'intext:"@{domain}" intext:password',
    '"{domain}" "credential" OR "login" site:pastebin.com OR site:ghostbin.com',
    '"{domain}" filetype:sql password',
    'site:github.com "{domain}" api_key OR apikey OR secret_key',
    '"{domain}" "database" "dump" OR "export"',
]


def get_dork_queries(domain: str) -> list:
    return [t.format(domain=domain) for t in DORK_TEMPLATES]


async def _ddg_search(query: str, client: httpx.AsyncClient) -> list:
    """DuckDuckGo HTML scrape — no API key needed."""
    results = []
    try:
        resp = await client.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query, "b": "", "kl": "us-en"},
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for result in soup.select(".result")[:6]:
                title_el = result.select_one(".result__title a")
                snippet_el = result.select_one(".result__snippet")
                url_el = result.select_one(".result__url")
                if title_el:
                    results.append({
                        "title": title_el.get_text(strip=True),
                        "url": title_el.get("href", ""),
                        "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
                        "display_url": url_el.get_text(strip=True) if url_el else "",
                    })
    except Exception:
        pass
    return results


async def _serp_search(query: str, client: httpx.AsyncClient, serp_key: str) -> list:
    results = []
    try:
        resp = await client.get(
            "https://serpapi.com/search",
            params={"q": query, "api_key": serp_key, "num": 10, "engine": "google"},
        )
        if resp.status_code == 200:
            for item in resp.json().get("organic_results", [])[:8]:
                results.append({
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "display_url": item.get("displayed_link", ""),
                })
    except Exception:
        pass
    return results


def _classify_result(url: str, snippet: str, domain: str) -> dict:
    """Classify a search result into a breach finding."""
    url_lower = url.lower()
    snippet_lower = snippet.lower()

    source_label = "Web"
    source_type = "dork"
    severity = "low"
    data_types = []

    # Source classification
    if "pastebin.com" in url_lower or "ghostbin" in url_lower or "rentry.co" in url_lower:
        source_label = "Paste Site"
        source_type = "paste"
        severity = "high"
        data_types = ["Email", "Password (possible)"]
    elif "github.com" in url_lower or "gitlab.com" in url_lower:
        source_label = "GitHub / GitLab"
        source_type = "git"
        severity = "high"
        data_types = ["Email", "API Key / Secret"]
    elif "trello.com" in url_lower or "jira" in url_lower:
        source_label = "Project Management"
        source_type = "collab"
        severity = "medium"
        data_types = ["Email", "Credentials (config possible)"]
    elif any(w in url_lower for w in ("raidforums", "breachforums", "exploit.in", "leakbase")):
        source_label = "Hack Forum"
        source_type = "forum"
        severity = "critical"
        data_types = ["Email", "Password", "Database dump"]
    elif "sql" in snippet_lower or "dump" in snippet_lower:
        source_label = "Database Dump"
        source_type = "db_dump"
        severity = "critical"
        data_types = ["Email", "Password hash", "PII"]

    # Data type detection from snippet
    if "password" in snippet_lower and "password" not in [d.lower() for d in data_types]:
        data_types.append("Password")
    if "email" in snippet_lower and "email" not in [d.lower() for d in data_types]:
        data_types.append("Email")
    if not data_types:
        data_types = ["Unknown — review required"]

    # Extract any emails from snippet
    emails = re.findall(rf"[\w.+%-]+@{re.escape(domain)}", snippet, re.I)
    masked = []
    for em in emails[:5]:
        parts = em.split("@")
        if len(parts) == 2:
            local = parts[0]
            m = (local[:2] + "***" + local[-1] if len(local) > 2 else local[0] + "***") + "@" + parts[1]
            masked.append(m)

    return {
        "source_label": source_label,
        "source_type": source_type,
        "severity": severity,
        "data_types": data_types,
        "masked_emails": masked,
    }


async def search(
    domain: str,
    client: httpx.AsyncClient,
    serp_key: Optional[str] = None,
) -> list:
    """Run high-priority dork queries and return structured findings."""
    findings = []

    # Prioritized dork queries to actively run (limit to avoid rate limits)
    active_queries = [
        f'site:pastebin.com "@{domain}"',
        f'site:github.com "@{domain}" password OR secret',
        f'"{domain}" "leaked" OR "breach" -site:{domain}',
    ]

    for query in active_queries:
        if serp_key:
            results = await _serp_search(query, client, serp_key)
        else:
            results = await _ddg_search(query, client)

        if not results:
            continue

        classified_results = []
        all_emails = set()
        for r in results:
            cls = _classify_result(r["url"], r["snippet"], domain)
            all_emails.update(cls["masked_emails"])
            classified_results.append({
                **r,
                "classification": cls,
            })

        if classified_results:
            severities = [r["classification"]["severity"] for r in classified_results]
            top_severity = sorted(severities, key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 4))[0]

            all_types = set()
            for r in classified_results:
                all_types.update(r["classification"]["data_types"])

            findings.append({
                "source": f"Dork — {query[:60]}",
                "source_type": "dork",
                "breach_name": f"Dork results: {query[:80]}",
                "date": None,
                "affected_accounts": len(classified_results),
                "data_types": list(all_types),
                "sample_emails": list(all_emails)[:8],
                "source_url": f"https://duckduckgo.com/?q={query.replace(' ', '+')}",
                "description": f"Dork query '{query}' returned {len(classified_results)} results referencing {domain}. Review each URL for credential exposure.",
                "severity": top_severity,
                "dork_results": classified_results[:6],
                "query": query,
            })

    return findings
