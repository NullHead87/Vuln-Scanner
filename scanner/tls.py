import ssl
import socket
from datetime import datetime

async def check_tls(url: str) -> dict:
    findings = []
    score = 0

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme != "https":
            return {
                "score": 0,
                "max_score": 3,
                "findings": [{"check": "https", "status": "warning", "detail": "Site does not use HTTPS"}]
            }

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        # TLS version check
        if tls_version in ("TLSv1.3", "TLSv1.2"):
            findings.append({"check": "tls_version", "status": "ok", "detail": f"TLS version: {tls_version}"})
            score += 1
        else:
            findings.append({"check": "tls_version", "status": "warning", "detail": f"Outdated TLS: {tls_version}"})

        # Certificate expiry check
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            if days_left > 14:
                findings.append({"check": "cert_expiry", "status": "ok", "detail": f"Certificate valid for {days_left} days"})
                score += 1
            else:
                findings.append({"check": "cert_expiry", "status": "warning", "detail": f"Certificate expires in {days_left} days"})

        # Subject / CN check
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        findings.append({"check": "common_name", "status": "ok", "detail": f"CN: {cn}"})
        score += 1

    except ssl.SSLError as e:
        findings.append({"check": "ssl_error", "status": "error", "detail": str(e)})
    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {
        "score": score,
        "max_score": 3,
        "findings": findings
    }