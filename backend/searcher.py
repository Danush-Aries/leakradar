import asyncio
import httpx
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional

from sources import hibp, code_search, paste_search, dork_search


def _normalize_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if raw.startswith("http"):
        parsed = urlparse(raw)
        raw = parsed.netloc or raw
    raw = raw.lstrip("www.")
    raw = raw.split("/")[0]
    raw = raw.split("?")[0]
    return raw


async def run_search(
    domain: str,
    hibp_key: Optional[str] = None,
    serp_key: Optional[str] = None,
    github_token: Optional[str] = None,
    gitlab_token: Optional[str] = None,
    bd_key: Optional[str] = None,
) -> dict:
    domain = _normalize_domain(domain)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(45.0),
        follow_redirects=True,
        headers={"User-Agent": "LeakRadar/1.0"},
    ) as client:
        tasks = [
            hibp.search(domain, client, hibp_key),
            code_search.search(domain, client, github_token, gitlab_token),
            paste_search.search(domain, client),
            dork_search.search(domain, client, serp_key),
        ]
        if bd_key:
            tasks.append(paste_search.search_breachdirectory(domain, client, bd_key))

        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    errors = []
    for r in results:
        if isinstance(r, Exception):
            errors.append(str(r))
        elif isinstance(r, list):
            findings.extend(r)

    # Sort: critical → high → medium → low → info
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x.get("severity", "info"), 4))

    # Summary stats
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_accounts = 0
    all_data_types = set()
    for f in findings:
        sev = f.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        if f.get("affected_accounts"):
            total_accounts += f["affected_accounts"]
        all_data_types.update(f.get("data_types", []))

    return {
        "domain": domain,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "total_affected_accounts": total_accounts,
        "severity_summary": severity_counts,
        "data_types_found": sorted(all_data_types),
        "findings": findings,
        "dork_queries": dork_search.get_dork_queries(domain),
        "keyless": not any([hibp_key, serp_key, github_token, gitlab_token, bd_key]),
        "errors": errors,
    }
