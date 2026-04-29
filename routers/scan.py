import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, HttpUrl
from io import BytesIO

from database import get_db
from models import ScanResult
from scanner.headers import check_headers
from scanner.tls import check_tls
from scanner.redirects import check_redirects
from scanner.dns_check import check_dns
from scanner.methods import check_methods
from scanner.cookies import check_cookies
from scanner.ports import check_ports
from scanner.subdomains import check_subdomains

router = APIRouter(prefix="/api", tags=["scanner"])


class ScanRequest(BaseModel):
    url: HttpUrl


@router.post("/scan", summary="Run a security scan on a URL")
async def run_scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    url = str(request.url)

    headers_result = await check_headers(url)
    tls_result = await check_tls(url)
    redirects_result = await check_redirects(url)
    dns_result = await check_dns(url)
    methods_result = await check_methods(url)
    cookies_result = await check_cookies(url)
    ports_result = await check_ports(url)
    subdomains_result = await check_subdomains(url)

    info_findings = []
    from urllib.parse import urlparse
    parsed = urlparse(url)
    info_findings.append({
        "check": "robots_txt",
        "status": "info",
        "detail": f"Check manually: {parsed.scheme}://{parsed.hostname}/robots.txt"
    })
    info_findings.append({
        "check": "sitemap",
        "status": "info",
        "detail": f"Check manually: {parsed.scheme}://{parsed.hostname}/sitemap.xml"
    })

    overall = (
        headers_result["score"] +
        tls_result["score"] +
        dns_result["score"] +
        cookies_result.get("score", 0)
    )

    max_score = (
        headers_result["max_score"] +
        tls_result["max_score"] +
        dns_result["max_score"] +
        cookies_result.get("max_score", 3)
    )

    scan = ScanResult(
        url=url,
        status="completed",
        headers_score=headers_result["score"],
        tls_score=tls_result["score"],
        dns_score=dns_result["score"],
        cookies_score=cookies_result.get("score", 0),
        overall_score=overall,
        headers_detail=json.dumps(headers_result["findings"]),
        tls_detail=json.dumps(tls_result["findings"]),
        redirects_detail=json.dumps(redirects_result["findings"]),
        dns_detail=json.dumps(dns_result["findings"]),
        methods_detail=json.dumps(methods_result["findings"]),
        cookies_detail=json.dumps(cookies_result["findings"]),
        ports_detail=json.dumps(ports_result["findings"]),
        subdomains_detail=json.dumps(subdomains_result["findings"]),
        info_detail=json.dumps(info_findings),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    return {
        "id": scan.id,
        "url": url,
        "overall_score": overall,
        "max_score": max_score,
        "created_at": scan.created_at,
        "results": {
            "headers": headers_result,
            "tls": tls_result,
            "redirects": redirects_result,
            "dns": dns_result,
            "methods": methods_result,
            "cookies": cookies_result,
            "ports": ports_result,
            "subdomains": subdomains_result,
            "info": {"findings": info_findings},
        }
    }


@router.get("/results", summary="List all past scan results")
async def list_results(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanResult).order_by(ScanResult.created_at.desc())
    )
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "url": s.url,
            "overall_score": s.overall_score,
            "status": s.status,
            "created_at": s.created_at,
        }
        for s in scans
    ]


@router.get("/results/{scan_id}", summary="Get a single scan result by ID")
async def get_result(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": scan.id,
        "url": scan.url,
        "overall_score": scan.overall_score,
        "status": scan.status,
        "created_at": scan.created_at,
        "results": {
            "headers": {"score": scan.headers_score, "findings": json.loads(scan.headers_detail or "[]")},
            "tls": {"score": scan.tls_score, "findings": json.loads(scan.tls_detail or "[]")},
            "redirects": {"findings": json.loads(scan.redirects_detail or "[]")},
            "dns": {"score": scan.dns_score, "findings": json.loads(scan.dns_detail or "[]")},
            "methods": {"findings": json.loads(scan.methods_detail or "[]")},
            "cookies": {"score": scan.cookies_score, "findings": json.loads(scan.cookies_detail or "[]")},
            "ports": {"findings": json.loads(scan.ports_detail or "[]")},
            "subdomains": {"findings": json.loads(scan.subdomains_detail or "[]")},
            "info": {"findings": json.loads(scan.info_detail or "[]")},
        }
    }


@router.get("/results/{scan_id}/pdf", summary="Download scan result as PDF")
async def download_pdf(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    pdf_bytes = generate_pdf(scan)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"}
    )


def generate_pdf(scan: ScanResult) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )

    WIDTH, HEIGHT = A4
    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        'Title', fontSize=22, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1a1a2e'), spaceAfter=4
    )
    style_subtitle = ParagraphStyle(
        'Subtitle', fontSize=10, fontName='Helvetica',
        textColor=colors.HexColor('#555570'), spaceAfter=16
    )
    style_section = ParagraphStyle(
        'Section', fontSize=13, fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1a1a2e'), spaceBefore=14, spaceAfter=6
    )
    style_body = ParagraphStyle(
        'Body', fontSize=9, fontName='Helvetica',
        textColor=colors.HexColor('#333344'), spaceAfter=3, leading=14
    )
    style_mono = ParagraphStyle(
        'Mono', fontSize=8, fontName='Courier',
        textColor=colors.HexColor('#444455'), spaceAfter=2, leading=12
    )

    STATUS_COLORS = {
        "ok":      colors.HexColor('#00aa55'),
        "missing": colors.HexColor('#cc2244'),
        "warning": colors.HexColor('#cc7700'),
        "info":    colors.HexColor('#4455aa'),
        "error":   colors.HexColor('#cc2244'),
    }

    def badge_color(status):
        return STATUS_COLORS.get(status, colors.gray)

    def findings_table(findings):
        if not findings:
            return Spacer(1, 4)
        data = []
        for f in findings:
            status = f.get("status", "info")
            key = f.get("header") or f.get("check", "")
            detail = f.get("value") or f.get("detail") or ""
            color = badge_color(status)
            data.append([
                Paragraph(f'<font color="{color.hexval()}">{status.upper()}</font>', style_mono),
                Paragraph(key, style_mono),
                Paragraph(str(detail)[:80], style_mono),
            ])

        t = Table(data, colWidths=[22*mm, 55*mm, 93*mm])
        t.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#f8f8fc'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#ddddee')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        return t

    overall = scan.overall_score
    max_s = 15
    pct = round((overall / max_s) * 100) if max_s else 0
    if pct >= 70:
        score_color = colors.HexColor('#00aa55')
    elif pct >= 40:
        score_color = colors.HexColor('#cc7700')
    else:
        score_color = colors.HexColor('#cc2244')

    created = scan.created_at.strftime("%d.%m.%Y %H:%M") if scan.created_at else "—"

    story = []

    story.append(Paragraph("Vuln-Scanner", style_title))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Tietoturvaraportti", style_subtitle))
    story.append(Paragraph(f"{scan.url}", style_subtitle))

    summary_data = [
        ["Kohde", scan.url],
        ["Skannausaika", created],
        ["Kokonaispistemäärä", f"{overall} / {max_s}  ({pct}%)"],
    ]
    summary_table = Table(summary_data, colWidths=[40*mm, 130*mm])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#555570')),
        ('TEXTCOLOR', (1, 2), (1, 2), score_color),
        ('FONTNAME', (1, 2), (1, 2), 'Helvetica-Bold'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#ddddee')),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f8fc')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    sections = [
        ("HTTP Security Headers", json.loads(scan.headers_detail or "[]")),
        ("TLS / SSL", json.loads(scan.tls_detail or "[]")),
        ("Uudelleenohjaukset", json.loads(scan.redirects_detail or "[]")),
        ("DNS-tarkistukset", json.loads(scan.dns_detail or "[]")),
        ("HTTP-metodit", json.loads(scan.methods_detail or "[]")),
        ("Evästeet", json.loads(scan.cookies_detail or "[]")),
        ("Portit", json.loads(scan.ports_detail or "[]")),
        ("Subdomainit", json.loads(scan.subdomains_detail or "[]")),
        ("Info", json.loads(scan.info_detail or "[]")),
    ]

    for title, findings in sections:
        story.append(Paragraph(title, style_section))
        story.append(findings_table(findings))
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#ddddee')))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Raportti generoitu: {created} | Vuln-Scanner v1.0 | JAMK 2026",
        ParagraphStyle('Footer', fontSize=7, fontName='Helvetica',
                       textColor=colors.HexColor('#aaaacc'), alignment=TA_CENTER)
    ))

    doc.build(story)
    return buffer.getvalue()