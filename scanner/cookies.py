import httpx

async def check_cookies(url: str) -> dict:
    findings = []
    score = 0

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            response = await client.get(url)

        cookies = response.cookies
        raw_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else []

        if not raw_headers:
            raw_set_cookie = response.headers.get("set-cookie", "")
            raw_headers = [raw_set_cookie] if raw_set_cookie else []

        if not raw_headers:
            findings.append({
                "check": "cookies",
                "status": "info",
                "detail": "Ei evästeitä asetettu"
            })
            return {"score": 0, "max_score": 0, "findings": findings}

        all_secure = True
        all_httponly = True
        all_samesite = True

        for cookie_header in raw_headers:
            lower = cookie_header.lower()
            name = cookie_header.split("=")[0].strip()

            secure = "secure" in lower
            httponly = "httponly" in lower
            samesite = "samesite" in lower

            if not secure:
                all_secure = False
                findings.append({"check": "secure_flag", "status": "warning", "detail": f"{name} — Secure-lippu puuttuu"})
            if not httponly:
                all_httponly = False
                findings.append({"check": "httponly_flag", "status": "warning", "detail": f"{name} — HttpOnly-lippu puuttuu"})
            if not samesite:
                all_samesite = False
                findings.append({"check": "samesite_flag", "status": "warning", "detail": f"{name} — SameSite-lippu puuttuu"})

        if all_secure:
            findings.append({"check": "secure_flag", "status": "ok", "detail": "Kaikissa evästeissä Secure-lippu"})
            score += 1
        if all_httponly:
            findings.append({"check": "httponly_flag", "status": "ok", "detail": "Kaikissa evästeissä HttpOnly-lippu"})
            score += 1
        if all_samesite:
            findings.append({"check": "samesite_flag", "status": "ok", "detail": "Kaikissa evästeissä SameSite-lippu"})
            score += 1

    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {
        "score": score,
        "max_score": 3,
        "findings": findings
    }