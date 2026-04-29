import httpx

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "PATCH", "OPTIONS"]

async def check_methods(url: str) -> dict:
    findings = []

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for method in DANGEROUS_METHODS:
                try:
                    response = await client.request(method, url)
                    if response.status_code < 400:
                        findings.append({
                            "check": f"method_{method.lower()}",
                            "status": "warning",
                            "detail": f"{method} hyväksytty — statuskoodi {response.status_code}"
                        })
                    else:
                        findings.append({
                            "check": f"method_{method.lower()}",
                            "status": "ok",
                            "detail": f"{method} estetty — statuskoodi {response.status_code}"
                        })
                except Exception:
                    findings.append({
                        "check": f"method_{method.lower()}",
                        "status": "info",
                        "detail": f"{method} — ei vastausta"
                    })

    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {"findings": findings}