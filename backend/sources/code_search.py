"""
Keyless code search across GitHub/GitLab/Bitbucket via:
  - grep.app        — searches GitHub, no key needed
  - sourcegraph.com — searches GitHub/GitLab/Bitbucket, no key needed
  - searchcode.com  — additional code search, no key needed

GitHub/GitLab tokens still upgrade to the native APIs for higher limits.
"""
import httpx
import re
import base64
import asyncio
from typing import Optional
from sources.github_search import (
    _extract_findings, _data_types_from_findings,
    _severity_from_findings, _build_snippets, _mask_email,
    GITHUB_QUERIES, GITLAB_QUERIES,
    search_github, search_gitlab,
)


# ── grep.app (no key, searches GitHub) ───────────────────────────────────────

GREP_QUERIES = [
    '"@{domain}" password',
    '"@{domain}" secret',
    '"@{domain}" api_key',
    '"{domain}" .env',
    '"{domain}" passwd',
    '"@{domain}" token',
]


async def _grepapp_query(query: str, domain: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await client.get(
            "https://grep.app/api/search",
            params={"q": query, "words": "false", "regexp": "false"},
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "application/json",
                "Referer": "https://grep.app/",
            },
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return None

        aggregate = {
            "emails": set(), "passwords": [], "api_keys": [],
            "tokens": [], "secrets": [], "special": [],
            "private_keys": False, "connection_strings": [],
        }
        file_hits = []
        snippets = []
        repos_seen = set()

        for hit in hits[:10]:
            repo = hit.get("repo", {}).get("raw", "")
            path = hit.get("path", {}).get("raw", "")
            branch = hit.get("branch", {}).get("raw", "HEAD")

            if repo:
                repos_seen.add(repo)

            # Raw URL on GitHub
            raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}" if repo else ""
            html_url = f"https://github.com/{repo}/blob/{branch}/{path}" if repo else ""

            file_hits.append({
                "repo": repo,
                "path": path,
                "url": html_url,
                "raw_url": raw_url,
            })

            # Content snippets from grep.app response
            content_fragments = hit.get("content", {}).get("snippet", [])
            for frag in content_fragments[:3]:
                text = frag.get("fragment", "")
                if text:
                    snippets.append(text[:150].strip())

            # Also try fetching raw content for deeper extraction
            if raw_url:
                try:
                    cr = await client.get(raw_url, timeout=8.0)
                    if cr.status_code == 200:
                        content = cr.text
                        extracted = _extract_findings(content, domain)
                        aggregate["emails"].update(extracted["emails"])
                        aggregate["passwords"].extend(extracted["passwords"][:2])
                        aggregate["api_keys"].extend(extracted["api_keys"][:2])
                        aggregate["tokens"].extend(extracted["tokens"][:2])
                        aggregate["secrets"].extend(extracted["secrets"][:2])
                        aggregate["special"].extend(extracted["special"][:3])
                        aggregate["connection_strings"].extend(extracted["connection_strings"][:1])
                        if extracted["private_keys"]:
                            aggregate["private_keys"] = True
                        if not snippets:
                            snippets = _build_snippets(content, domain)
                except Exception:
                    pass

        data_types = _data_types_from_findings(aggregate)
        severity = _severity_from_findings(aggregate, len(hits))

        exposed_values = []
        exposed_values.extend([f"password: {p}" for p in list(set(aggregate["passwords"]))[:3]])
        exposed_values.extend([f"api_key: {k}" for k in list(set(aggregate["api_keys"]))[:3]])
        exposed_values.extend([f"token: {t}" for t in list(set(aggregate["tokens"]))[:3]])
        exposed_values.extend(aggregate["special"][:5])
        exposed_values.extend([f"db: {c}" for c in aggregate["connection_strings"][:2]])

        total = data.get("hits", {}).get("total", {})
        total_count = total.get("value", len(hits)) if isinstance(total, dict) else len(hits)

        return {
            "source": "grep.app (GitHub)",
            "source_type": "git",
            "breach_name": f"Code leak — {query}",
            "date": None,
            "affected_accounts": total_count,
            "data_types": data_types,
            "sample_emails": [_mask_email(e) for e in list(aggregate["emails"])[:10]],
            "exposed_values": exposed_values[:10],
            "source_url": f"https://grep.app/search?q={query}",
            "description": (
                f"grep.app found {total_count} public code file(s) matching '{query}'. "
                f"Repositories: {', '.join(list(repos_seen)[:4])}."
            ),
            "severity": severity,
            "snippets": list(dict.fromkeys(snippets))[:4],
            "repos": list(repos_seen)[:6],
            "file_hits": file_hits[:6],
            "query": query,
        }

    except Exception:
        return None


async def search_grepapp(domain: str, client: httpx.AsyncClient) -> list:
    queries = [q.format(domain=domain) for q in GREP_QUERIES[:4]]
    tasks = [_grepapp_query(q, domain, client) for q in queries]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r and isinstance(r, dict)]


# ── sourcegraph.com (no key, searches GitHub + GitLab + Bitbucket) ────────────

SOURCEGRAPH_QUERIES = [
    '"@{domain}" password',
    '"@{domain}" api_key OR secret OR token',
    'file:.env "{domain}"',
    'file:config "{domain}" password',
]


async def _sourcegraph_query(query: str, domain: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        # Sourcegraph streaming search API
        resp = await client.get(
            "https://sourcegraph.com/.api/search/stream",
            params={
                "q": f"context:global {query}",
                "display": "15",
                "version": "V3",
            },
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/event-stream",
            },
            timeout=20.0,
        )
        if resp.status_code != 200:
            return None

        # Parse SSE stream — extract 'matches' events
        matches = []
        for line in resp.text.splitlines():
            if line.startswith("data:") and '"type":"content"' in line:
                try:
                    import json
                    payload = json.loads(line[5:])
                    if isinstance(payload, list):
                        matches.extend(payload)
                    elif isinstance(payload, dict):
                        matches.append(payload)
                except Exception:
                    pass

        if not matches:
            return None

        aggregate = {
            "emails": set(), "passwords": [], "api_keys": [],
            "tokens": [], "secrets": [], "special": [],
            "private_keys": False, "connection_strings": [],
        }
        repos_seen = set()
        file_hits = []
        snippets = []

        for m in matches[:8]:
            repo_name = m.get("repository", "")
            file_path = m.get("path", "")
            if repo_name:
                repos_seen.add(repo_name)
            url = m.get("url", "")
            file_hits.append({"repo": repo_name, "path": file_path, "url": f"https://sourcegraph.com{url}" if url else ""})

            for chunk in m.get("chunkMatches", [])[:3]:
                content_str = chunk.get("content", "")
                if content_str:
                    snippets.append(content_str[:150].strip())
                    extracted = _extract_findings(content_str, domain)
                    aggregate["emails"].update(extracted["emails"])
                    aggregate["passwords"].extend(extracted["passwords"][:1])
                    aggregate["api_keys"].extend(extracted["api_keys"][:1])
                    aggregate["tokens"].extend(extracted["tokens"][:1])
                    aggregate["special"].extend(extracted["special"][:2])

        data_types = _data_types_from_findings(aggregate)
        severity = _severity_from_findings(aggregate, len(matches))

        exposed = []
        exposed.extend([f"password: {p}" for p in list(set(aggregate["passwords"]))[:2]])
        exposed.extend([f"api_key: {k}" for k in list(set(aggregate["api_keys"]))[:2]])
        exposed.extend(aggregate["special"][:4])

        return {
            "source": "Sourcegraph (GitHub/GitLab/BB)",
            "source_type": "git",
            "breach_name": f"Code leak — {query}",
            "date": None,
            "affected_accounts": len(matches),
            "data_types": data_types,
            "sample_emails": [_mask_email(e) for e in list(aggregate["emails"])[:8]],
            "exposed_values": exposed[:8],
            "source_url": f"https://sourcegraph.com/search?q=context:global+{query}&patternType=literal",
            "description": f"Sourcegraph found {len(matches)} file(s) across GitHub/GitLab/Bitbucket matching '{query}'.",
            "severity": severity,
            "snippets": list(dict.fromkeys(snippets))[:4],
            "repos": list(repos_seen)[:5],
            "file_hits": file_hits[:5],
            "query": query,
        }

    except Exception:
        return None


async def search_sourcegraph(domain: str, client: httpx.AsyncClient) -> list:
    queries = [q.format(domain=domain) for q in SOURCEGRAPH_QUERIES[:3]]
    tasks = [_sourcegraph_query(q, domain, client) for q in queries]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r and isinstance(r, dict)]


# ── searchcode.com (no key needed) ───────────────────────────────────────────

async def search_searchcode(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    queries = [
        f'"@{domain}" password',
        f'"@{domain}" secret',
    ]
    for q in queries[:1]:
        try:
            resp = await client.get(
                "https://searchcode.com/api/codesearch_I/",
                params={"q": q, "per_page": 10, "p": 0},
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            results = data.get("results", [])
            if not results:
                continue

            emails = set()
            file_hits = []
            for r in results[:6]:
                repo = r.get("repo", "")
                path = r.get("filename", "")
                url = r.get("url", "")
                file_hits.append({"repo": repo, "path": path, "url": url})
                for line in r.get("lines", {}).values():
                    found = re.findall(rf"[\w.+%-]+@{re.escape(domain)}", line, re.I)
                    emails.update(found[:3])

            total = data.get("total", len(results))
            findings.append({
                "source": "searchcode.com",
                "source_type": "git",
                "breach_name": f"Code leak — {q}",
                "date": None,
                "affected_accounts": total,
                "data_types": ["Email addresses", "Credentials", "Source Code"],
                "sample_emails": [_mask_email(e) for e in list(emails)[:8]],
                "exposed_values": [],
                "source_url": f"https://searchcode.com/?q={q}",
                "description": f"searchcode.com found {total} file(s) matching '{q}'.",
                "severity": "high" if emails else "medium",
                "snippets": [],
                "repos": [],
                "file_hits": file_hits[:5],
                "query": q,
            })
        except Exception:
            continue
    return findings


# ── Main entry: keyless by default, API upgrades if tokens given ──────────────

async def search(
    domain: str,
    client: httpx.AsyncClient,
    github_token: Optional[str] = None,
    gitlab_token: Optional[str] = None,
) -> list:
    if github_token or gitlab_token:
        # Use native APIs when tokens available
        tasks = []
        if github_token:
            tasks.append(search_github(domain, client, github_token))
        if gitlab_token:
            tasks.append(search_gitlab(domain, client, gitlab_token))
        # Also run keyless sources in parallel for broader coverage
        tasks.extend([
            search_grepapp(domain, client),
            search_sourcegraph(domain, client),
        ])
    else:
        # Fully keyless
        tasks = [
            search_grepapp(domain, client),
            search_sourcegraph(domain, client),
            search_searchcode(domain, client),
        ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings = []
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
    return findings
