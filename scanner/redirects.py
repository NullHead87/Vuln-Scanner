import httpx

async def check_redirects(url: str) -> dict:
    findings = []

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(url)

        # Check for open redirect indicators
        location = response.headers.get("location", "")
        if response.status_code in (301, 302, 303, 307, 308):
            if location.startswith("http") and not _same_domain(url, location):
                findings.append({
                    "check": "open_redirect",
                    "status": "warning",
                    "detail": f"Redirects to external domain: {location}"
                })
            else:
                findings.append({
                    "check": "redirect",
                    "status": "info",
                    "detail": f"Redirects to: {location}"
                })
        else:
            findings.append({
                "check": "redirect",
                "status": "ok",
                "detail": "No redirect on root"
            })

        # HTTP to HTTPS redirect check
        if url.startswith("http://"):
            findings.append({
                "check": "http_to_https",
                "status": "warning" if response.status_code not in (301, 302) else "ok",
                "detail": "HTTP to HTTPS redirect " + ("present" if response.status_code in (301, 302) else "missing")
            })

    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {"findings": findings}


def _same_domain(original: str, redirect: str) -> bool:
    from urllib.parse import urlparse
    return urlparse(original).hostname == urlparse(redirect).hostname