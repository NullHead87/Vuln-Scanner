import dns.resolver

async def check_dns(url: str) -> dict:
    findings = []
    score = 0

    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname

        # SPF
        try:
            answers = dns.resolver.resolve(hostname, 'TXT')
            spf_found = any('v=spf1' in str(r) for r in answers)
            if spf_found:
                findings.append({"check": "spf", "status": "ok", "detail": "SPF-tietue löytyy"})
                score += 1
            else:
                findings.append({"check": "spf", "status": "missing", "detail": "SPF-tietuetta ei löydy"})
        except Exception:
            findings.append({"check": "spf", "status": "missing", "detail": "SPF-tietuetta ei löydy"})

        # DMARC
        try:
            answers = dns.resolver.resolve(f'_dmarc.{hostname}', 'TXT')
            dmarc_found = any('v=DMARC1' in str(r) for r in answers)
            if dmarc_found:
                findings.append({"check": "dmarc", "status": "ok", "detail": "DMARC-tietue löytyy"})
                score += 1
            else:
                findings.append({"check": "dmarc", "status": "missing", "detail": "DMARC-tietuetta ei löydy"})
        except Exception:
            findings.append({"check": "dmarc", "status": "missing", "detail": "DMARC-tietuetta ei löydy"})

        # DKIM (yleinen selector)
        try:
            answers = dns.resolver.resolve(f'default._domainkey.{hostname}', 'TXT')
            findings.append({"check": "dkim", "status": "ok", "detail": "DKIM-tietue löytyy (default selector)"})
            score += 1
        except Exception:
            findings.append({"check": "dkim", "status": "info", "detail": "DKIM ei löydy default-selectorilla — voi silti olla käytössä"})

    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {
        "score": score,
        "max_score": 3,
        "findings": findings
    }