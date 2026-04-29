import asyncio

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}

RISKY_PORTS = [21, 23, 3306, 5432, 6379, 27017]

async def check_port(hostname: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def check_ports(url: str) -> dict:
    findings = []

    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname

        tasks = {port: check_port(hostname, port) for port in COMMON_PORTS}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for (port, service), is_open in zip(COMMON_PORTS.items(), results):
            if isinstance(is_open, Exception):
                is_open = False

            if is_open:
                status = "warning" if port in RISKY_PORTS else "info"
                findings.append({
                    "check": f"port_{port}",
                    "status": status,
                    "detail": f"Portti {port} ({service}) on auki"
                })
            else:
                findings.append({
                    "check": f"port_{port}",
                    "status": "ok",
                    "detail": f"Portti {port} ({service}) suljettu"
                })

    except Exception as e:
        findings.append({"check": "error", "status": "error", "detail": str(e)})

    return {"findings": findings}