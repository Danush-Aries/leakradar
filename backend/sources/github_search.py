"""
Code hosting leak search: GitHub, GitLab, Bitbucket.
Finds leaked emails, passwords, API keys, .env files, config files.
"""
import httpx
import re
import base64
import asyncio
from typing import Optional


# ── Patterns ──────────────────────────────────────────────────────────────────

# What we look for inside file contents
SENSITIVE_PATTERNS = {
    "email":        r"[\w.+%-]+@{domain}",
    "password":     r"(?:password|passwd|pwd)\s*[=:\"']+\s*([^\s\"',;\n]{6,})",
    "api_key":      r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:\"']+\s*([A-Za-z0-9_\-]{16,})",
    "token":        r"(?:token|bearer|auth[_-]?token)\s*[=:\"']+\s*([A-Za-z0-9_\-\.]{20,})",
    "secret":       r"(?:secret|client[_-]?secret)\s*[=:\"']+\s*([^\s\"',;\n]{10,})",
    "private_key":  r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "aws_key":      r"AKIA[0-9A-Z]{16}",
    "aws_secret":   r"(?:aws[_-]?secret|AWS_SECRET)\s*[=:\"']+\s*([A-Za-z0-9/+]{40})",
    "connection_str": r"(?:mongodb|postgresql|mysql|redis|amqp)://[^\s\"'<>]{10,}",
    "jwt":          r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "slack_token":  r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "github_token": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
    "google_key":   r"AIza[0-9A-Za-z\-_]{35}",
    "stripe_key":   r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
}

# GitHub Code Search queries
GITHUB_QUERIES = [
    '"@{domain}" password',
    '"@{domain}" secret OR api_key OR token',
    '"{domain}" .env OR config',
    '"@{domain}" passwd OR credentials',
    'filename:.env "{domain}"',
    'filename:config.yml "{domain}" password',
    'filename:settings.py "{domain}" SECRET',
    'filename:database.yml "{domain}"',
    'filename:wp-config.php "{domain}"',
    '"{domain}" private_key OR rsa_key',
]

# GitLab search queries (same structure)
GITLAB_QUERIES = [
    '"@{domain}" password',
    '"@{domain}" api_key OR secret',
    '"{domain}" .env',
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2:
        return email
    local, dom = parts
    if len(local) <= 2:
        return f"{local[0]}***@{dom}"
    return f"{local[:2]}***{local[-1]}@{dom}"


def _mask_secret(val: str) -> str:
    if len(val) <= 6:
        return "***"
    return val[:3] + "***" + val[-2:]


def _extract_findings(content: str, domain: str) -> dict:
    """Extract all sensitive data from file content."""
    found = {
        "emails": set(),
        "passwords": [],
        "api_keys": [],
        "tokens": [],
        "secrets": [],
        "special": [],   # AWS, Stripe, Slack, etc.
        "private_keys": False,
        "connection_strings": [],
    }

    # Emails
    for m in re.findall(rf"[\w.+%-]+@{re.escape(domain)}", content, re.I):
        found["emails"].add(m)

    # Passwords
    for m in re.findall(SENSITIVE_PATTERNS["password"], content, re.I):
        if m and len(m) > 3:
            found["passwords"].append(_mask_secret(m))

    # API keys
    for m in re.findall(SENSITIVE_PATTERNS["api_key"], content, re.I):
        found["api_keys"].append(_mask_secret(m))

    # Tokens
    for m in re.findall(SENSITIVE_PATTERNS["token"], content, re.I):
        if m and len(m) > 8:
            found["tokens"].append(_mask_secret(m))

    # Secrets
    for m in re.findall(SENSITIVE_PATTERNS["secret"], content, re.I):
        if m and len(m) > 6:
            found["secrets"].append(_mask_secret(m))

    # AWS keys
    for m in re.findall(SENSITIVE_PATTERNS["aws_key"], content):
        found["special"].append(f"AWS Key: {_mask_secret(m)}")
    for m in re.findall(SENSITIVE_PATTERNS["aws_secret"], content, re.I):
        found["special"].append(f"AWS Secret: {_mask_secret(m)}")

    # Private key block
    if re.search(SENSITIVE_PATTERNS["private_key"], content):
        found["private_keys"] = True
        found["special"].append("Private key block detected")

    # JWT
    jwts = re.findall(SENSITIVE_PATTERNS["jwt"], content)
    if jwts:
        found["special"].append(f"{len(jwts)} JWT token(s)")

    # Slack
    for m in re.findall(SENSITIVE_PATTERNS["slack_token"], content):
        found["special"].append(f"Slack token: {_mask_secret(m)}")

    # GitHub token
    for m in re.findall(SENSITIVE_PATTERNS["github_token"], content):
        found["special"].append(f"GitHub PAT: {_mask_secret(m)}")

    # Stripe
    for m in re.findall(SENSITIVE_PATTERNS["stripe_key"], content):
        found["special"].append(f"Stripe key: {_mask_secret(m)}")

    # Google API key
    for m in re.findall(SENSITIVE_PATTERNS["google_key"], content):
        found["special"].append(f"Google API key: {_mask_secret(m)}")

    # Connection strings
    for m in re.findall(SENSITIVE_PATTERNS["connection_str"], content, re.I):
        found["connection_strings"].append(_mask_secret(m))

    return found


def _data_types_from_findings(f: dict) -> list:
    types = []
    if f["emails"]:          types.append("Email addresses")
    if f["passwords"]:       types.append("Passwords (plaintext)")
    if f["api_keys"]:        types.append("API Keys")
    if f["tokens"]:          types.append("Auth Tokens")
    if f["secrets"]:         types.append("Secrets / Keys")
    if f["private_keys"]:    types.append("Private Key (PEM)")
    if f["connection_strings"]: types.append("Database Connection Strings")
    if any("AWS" in s for s in f["special"]):    types.append("AWS Credentials")
    if any("Stripe" in s for s in f["special"]): types.append("Stripe API Keys")
    if any("Slack" in s for s in f["special"]):  types.append("Slack Tokens")
    if any("JWT" in s for s in f["special"]):    types.append("JWT Tokens")
    if any("GitHub" in s for s in f["special"]): types.append("GitHub Tokens")
    if any("Google" in s for s in f["special"]): types.append("Google API Keys")
    return types or ["Source Code Credential Exposure"]


def _severity_from_findings(f: dict, item_count: int) -> str:
    if f["private_keys"] or any("AWS" in s for s in f["special"]):
        return "critical"
    if f["passwords"] or f["emails"] or any("Stripe" in s for s in f["special"]):
        return "high"
    if f["api_keys"] or f["tokens"] or f["connection_strings"]:
        return "high"
    if f["secrets"] or f["special"]:
        return "medium"
    if item_count > 0:
        return "medium"
    return "low"


def _build_snippets(content: str, domain: str, max_lines: int = 4) -> list:
    """Extract relevant lines showing the context of the leak."""
    snippets = []
    lines = content.splitlines()
    sensitive_re = re.compile(
        r"password|passwd|secret|api[_\-]?key|token|private|credential|auth|key\s*=|aws",
        re.I
    )
    domain_re = re.compile(re.escape(domain), re.I)

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or len(line) > 200:
            continue
        if domain_re.search(line) or sensitive_re.search(line):
            snippets.append(line)
        if len(snippets) >= max_lines:
            break
    return snippets


# ── GitHub Search ─────────────────────────────────────────────────────────────

async def _github_query(
    query: str,
    domain: str,
    client: httpx.AsyncClient,
    headers: dict,
) -> Optional[dict]:
    try:
        resp = await client.get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": 10, "sort": "indexed"},
            headers=headers,
        )
        # Auth required — GitHub removed unauthenticated code search
        if resp.status_code in (401, 403):
            return {
                "source": "GitHub Code Search",
                "source_type": "git",
                "breach_name": f"GitHub — auth required for: {query}",
                "date": None,
                "affected_accounts": None,
                "data_types": ["Requires GitHub token"],
                "sample_emails": [],
                "exposed_values": [],
                "source_url": f"https://github.com/search?q={query}&type=code",
                "description": (
                    "GitHub Code Search now requires authentication. "
                    "Add a free GitHub token in Settings to search for leaked credentials, "
                    ".env files, API keys, and config files across millions of public repositories. "
                    f"Click 'View' to open this search manually in your browser."
                ),
                "severity": "info",
                "snippets": [],
                "repos": [],
                "file_hits": [],
                "needs_token": True,
            }
        if resp.status_code == 422:
            return None  # Query too complex
        if resp.status_code != 200:
            return None

        items = resp.json().get("items", [])
        if not items:
            return None

        aggregate = {
            "emails": set(), "passwords": [], "api_keys": [],
            "tokens": [], "secrets": [], "special": [],
            "private_keys": False, "connection_strings": [],
        }
        repos_seen = set()
        snippets = []
        file_hits = []

        for item in items[:8]:
            repo = item.get("repository", {})
            repo_name = repo.get("full_name", "")
            file_path = item.get("path", "")
            file_url = item.get("html_url", "")
            if repo_name:
                repos_seen.add(repo_name)

            file_hits.append({
                "repo": repo_name,
                "path": file_path,
                "url": file_url,
                "stars": repo.get("stargazers_count", 0),
            })

            # Fetch file content
            try:
                cr = await client.get(item["url"], headers=headers)
                if cr.status_code == 200:
                    data = cr.json()
                    raw = b""
                    if data.get("encoding") == "base64":
                        raw = base64.b64decode(data["content"].replace("\n", ""))
                    content = raw.decode("utf-8", errors="ignore")

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
        severity = _severity_from_findings(aggregate, len(items))

        # Build exposed_values list (masked)
        exposed_values = []
        exposed_values.extend([f"password: {p}" for p in list(set(aggregate["passwords"]))[:3]])
        exposed_values.extend([f"api_key: {k}" for k in list(set(aggregate["api_keys"]))[:3]])
        exposed_values.extend([f"token: {t}" for t in list(set(aggregate["tokens"]))[:3]])
        exposed_values.extend(aggregate["special"][:5])
        exposed_values.extend([f"db: {c}" for c in aggregate["connection_strings"][:2]])

        return {
            "source": "GitHub Code Search",
            "source_type": "git",
            "breach_name": f"GitHub leak — {query}",
            "date": None,
            "affected_accounts": len(items),
            "data_types": data_types,
            "sample_emails": [_mask_email(e) for e in list(aggregate["emails"])[:10]],
            "exposed_values": exposed_values[:10],
            "source_url": f"https://github.com/search?q={query}&type=code",
            "description": (
                f"Found {len(items)} public file(s) on GitHub matching '{query}'. "
                f"Repositories: {', '.join(list(repos_seen)[:4])}."
            ),
            "severity": severity,
            "snippets": snippets[:4],
            "repos": list(repos_seen)[:6],
            "file_hits": file_hits[:6],
            "query": query,
        }

    except Exception:
        return None


async def search_github(domain: str, client: httpx.AsyncClient, github_token: Optional[str] = None) -> list:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "LeakRadar/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    queries = [q.format(domain=domain) for q in GITHUB_QUERIES]
    # Without token: limit to 3 queries (rate limit: 10 req/min unauthenticated)
    # With token: run up to 6 queries (5000 req/hour)
    limit = 6 if github_token else 3

    tasks = [_github_query(q, domain, client, headers) for q in queries[:limit]]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for r in results:
        if r and isinstance(r, dict):
            findings.append(r)

    return findings


# ── GitLab Search ─────────────────────────────────────────────────────────────

async def search_gitlab(domain: str, client: httpx.AsyncClient, gitlab_token: Optional[str] = None) -> list:
    findings = []
    headers = {"User-Agent": "LeakRadar/1.0"}
    if gitlab_token:
        headers["PRIVATE-TOKEN"] = gitlab_token

    queries = [q.format(domain=domain) for q in GITLAB_QUERIES[:2]]

    for query in queries:
        try:
            resp = await client.get(
                "https://gitlab.com/api/v4/search",
                params={"scope": "blobs", "search": query, "per_page": 10},
                headers=headers,
            )
            if resp.status_code != 200:
                continue

            items = resp.json()
            if not items:
                continue

            emails = set()
            repos = set()
            snippets = []
            exposed = []

            for item in items[:6]:
                proj = item.get("project_id", "")
                repos.add(str(proj))
                content = item.get("data", "")
                if content:
                    extracted = _extract_findings(content, domain)
                    emails.update(extracted["emails"])
                    exposed.extend(extracted["special"][:2])
                    if not snippets:
                        snippets = _build_snippets(content, domain)

            if items:
                findings.append({
                    "source": "GitLab Code Search",
                    "source_type": "git",
                    "breach_name": f"GitLab leak — {query}",
                    "date": None,
                    "affected_accounts": len(items),
                    "data_types": ["Email", "Credentials", "Source Code"],
                    "sample_emails": [_mask_email(e) for e in list(emails)[:8]],
                    "exposed_values": exposed[:5],
                    "source_url": f"https://gitlab.com/search?search={query}&scope=blobs",
                    "description": f"Found {len(items)} GitLab file(s) matching '{query}'.",
                    "severity": "high" if emails or exposed else "medium",
                    "snippets": snippets[:3],
                    "repos": list(repos)[:5],
                    "query": query,
                })

        except Exception:
            continue

    return findings


# ── Bitbucket Search ──────────────────────────────────────────────────────────

async def search_bitbucket(domain: str, client: httpx.AsyncClient) -> list:
    """Bitbucket has no public code search API — use their search endpoint."""
    findings = []
    try:
        resp = await client.get(
            "https://api.bitbucket.org/2.0/search/code",
            params={"q": f'content:"{domain}" content:password', "pagelen": 10},
            headers={"User-Agent": "LeakRadar/1.0"},
        )
        if resp.status_code == 200:
            items = resp.json().get("values", [])
            if items:
                findings.append({
                    "source": "Bitbucket Code Search",
                    "source_type": "git",
                    "breach_name": f"Bitbucket credential exposure",
                    "date": None,
                    "affected_accounts": len(items),
                    "data_types": ["Email", "Credentials", "Source Code"],
                    "sample_emails": [],
                    "exposed_values": [],
                    "source_url": f"https://bitbucket.org/search?q=content%3A%22{domain}%22+content%3Apassword",
                    "description": f"Found {len(items)} Bitbucket file(s) containing '{domain}' with credential-related content.",
                    "severity": "medium",
                    "snippets": [],
                    "repos": [],
                })
    except Exception:
        pass
    return findings


# ── Main Entry Point ──────────────────────────────────────────────────────────

async def search(
    domain: str,
    client: httpx.AsyncClient,
    github_token: Optional[str] = None,
    gitlab_token: Optional[str] = None,
) -> list:
    tasks = [
        search_github(domain, client, github_token),
        search_gitlab(domain, client, gitlab_token),
        search_bitbucket(domain, client),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings = []
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
    return findings
