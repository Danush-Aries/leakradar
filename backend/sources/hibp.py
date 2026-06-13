import httpx
import re
from typing import Optional


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text).strip()


def _mask_email(local: str, domain: str) -> str:
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[:2]}***{local[-1]}@{domain}"


def _severity(breach: dict) -> str:
    classes = [d.lower() for d in breach.get("DataClasses", [])]
    count = breach.get("PwnCount", 0)
    has_passwords = any("password" in c for c in classes)
    has_financial = any(w in c for c in classes for w in ("credit", "bank", "payment", "financial"))
    if has_passwords and count > 1_000_000:
        return "critical"
    if has_passwords or has_financial:
        return "high"
    if count > 5_000_000:
        return "high"
    if count > 100_000:
        return "medium"
    return "low"


async def search(domain: str, client: httpx.AsyncClient, hibp_key: Optional[str] = None) -> list:
    findings = []
    headers = {"User-Agent": "LeakRadar/1.0"}
    if hibp_key:
        headers["hibp-api-key"] = hibp_key

    # Public endpoint — metadata for all breaches containing this domain
    try:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            headers=headers,
        )
        if resp.status_code == 200:
            for b in resp.json():
                findings.append({
                    "source": "HaveIBeenPwned",
                    "source_type": "hibp",
                    "breach_name": b.get("Name", "Unknown"),
                    "date": b.get("BreachDate"),
                    "affected_accounts": b.get("PwnCount"),
                    "data_types": b.get("DataClasses", []),
                    "sample_emails": [],
                    "source_url": f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name', '')}",
                    "description": _strip_html(b.get("Description", "")),
                    "severity": _severity(b),
                    "logo": b.get("LogoPath"),
                    "verified": not b.get("IsFabricated", False),
                })
    except Exception:
        pass

    # Keyed endpoint — per-account breach data for the domain
    if hibp_key:
        try:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers=headers,
            )
            if resp.status_code == 200:
                accounts = resp.json()
                for local, breach_names in list(accounts.items())[:50]:
                    masked = _mask_email(local, domain)
                    for name in breach_names:
                        for f in findings:
                            if f["breach_name"] == name and masked not in f["sample_emails"]:
                                f["sample_emails"].append(masked)
                                break
        except Exception:
            pass

    return findings
