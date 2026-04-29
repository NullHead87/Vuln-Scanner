import httpx

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "dev", "staging",
    "api", "test", "portal", "vpn", "remote", "shop",
    "blog", "app", "beta", "secure", "login", "cpanel"
]

async def check_subdomains(url: str) -> dict:
    findings = []

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        scheme = parsed.scheme

        parts = hostname.split(".")
        if len(parts) > 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = hostname

        async def probe(sub: str):
            target = f"{scheme}://{sub}.{base_domain}"
            try:
                async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
                    response = await client.get(target)
                    if response.status_code < 400:
                        return {
                            "check": f"subdomain_{sub}",
                            "status": "info",
                            "detail": f"{sub}.{base_domain} vastaa — statuskoodi {response.status_code}"
                        }
            except Exception:
                pass
            return None

        import asyncio
        results = await asyncio.gather(*[probe(sub) for sub in COMMON_SUBDOMAINS])
        found = [r for r in results if r is not None]

        if found:
            findings.extend(found)
        else:
            findings.append({
                "check": "subdomains",
                "status": "ok",
                "detail": "Ei yleisiä subdomaineja löydetty"
            })

    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {"findings": findings}