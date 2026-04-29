import httpx

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

async def check_headers(url: str) -> dict:
    findings = []
    score = 0

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}

        for header in SECURITY_HEADERS:
            if header in headers:
                findings.append({
                    "header": header,
                    "status": "present",
                    "value": headers[header]
                })
                score += 1
            else:
                findings.append({
                    "header": header,
                    "status": "missing",
                    "value": None
                })

        server = headers.get("server", None)
        if server:
            findings.append({
                "header": "server",
                "status": "warning",
                "value": f"Server version exposed: {server}"
            })

    except Exception as e:
        findings.append({"header": "error", "status": "error", "value": str(e)})

    return {
        "score": score,
        "max_score": len(SECURITY_HEADERS),
        "findings": findings
    }