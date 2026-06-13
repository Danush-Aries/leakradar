import httpx
import re
from typing import Optional


def _mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2:
        return email
    local, dom = parts
    if len(local) <= 2:
        return f"{local[0]}***@{dom}"
    return f"{local[:2]}***{local[-1]}@{dom}"


async def search(domain: str, client: httpx.AsyncClient) -> list:
    findings = []

    # psbdmp.ws — Pastebin archive search
    try:
        resp = await client.get(
            f"https://psbdmp.ws/api/search/{domain}",
            headers={"User-Agent": "LeakRadar/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            pastes = data.get("data", []) if isinstance(data, dict) else []
            if pastes:
                emails_found = set()
                urls = []
                for p in pastes[:15]:
                    pid = p.get("id", "")
                    if pid:
                        urls.append(f"https://pastebin.com/{pid}")
                    text = p.get("text", "") or p.get("snippet", "") or ""
                    found = re.findall(rf"[\w.+%-]+@{re.escape(domain)}", text, re.I)
                    emails_found.update(found[:5])

                severity = "critical" if len(pastes) > 20 else "high" if len(pastes) > 5 else "medium"
                findings.append({
                    "source": "Pastebin (psbdmp.ws)",
                    "source_type": "paste",
                    "breach_name": f"Pastebin dumps — {len(pastes)} paste(s) found",
                    "date": None,
                    "affected_accounts": len(pastes),
                    "data_types": ["Email", "Password (plaintext possible)", "Credentials"],
                    "sample_emails": [_mask_email(e) for e in list(emails_found)[:10]],
                    "source_url": urls[0] if urls else f"https://psbdmp.ws/search/{domain}",
                    "description": (
                        f"Found {len(pastes)} Pastebin dump(s) referencing {domain}. "
                        "Credential dumps posted to Pastebin often contain plaintext email:password combos."
                    ),
                    "severity": severity,
                    "paste_urls": urls[:5],
                })
    except Exception:
        pass

    # publicwww approach — search common paste sites via DDG
    paste_sites = [
        ("Ghostbin", f"site:ghostbin.com \"{domain}\""),
        ("Hastebin", f"site:hastebin.com \"{domain}\""),
        ("Rentry", f"site:rentry.co \"{domain}\""),
    ]

    # We won't actively scrape Google here — just add as manual dork suggestions
    # (those go into the dork_queries output from the main searcher)

    return findings


async def search_breachdirectory(domain: str, client: httpx.AsyncClient, api_key: Optional[str] = None) -> list:
    """BreachDirectory.org has a free read-only API."""
    findings = []
    if not api_key:
        return findings  # requires key

    try:
        resp = await client.get(
            "https://breachdirectory.p.rapidapi.com/",
            params={"func": "auto", "term": domain},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("result", [])
            if results:
                emails = set()
                passwords = set()
                for item in results[:30]:
                    em = item.get("email", "")
                    pw = item.get("password", "")
                    if em:
                        emails.add(em)
                    if pw:
                        passwords.add(pw[:3] + "***")

                findings.append({
                    "source": "BreachDirectory",
                    "source_type": "breach_db",
                    "breach_name": f"BreachDirectory — {len(results)} record(s)",
                    "date": None,
                    "affected_accounts": len(results),
                    "data_types": ["Email", "Password Hash / Plaintext"],
                    "sample_emails": [_mask_email(e) if "@" in e else e for e in list(emails)[:10]],
                    "sample_passwords": list(passwords)[:5],
                    "source_url": f"https://breachdirectory.org/?query={domain}",
                    "description": f"BreachDirectory found {len(results)} exposed records for {domain}.",
                    "severity": "critical" if len(results) > 100 else "high",
                })
    except Exception:
        pass

    return findings
