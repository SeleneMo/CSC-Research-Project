from fpdf import FPDF
from fpdf.enums import XPos, YPos

from app.models.schemas import CveTaxonomyMap, ScanLogEntry


def _safe_pdf_text(text: str) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("—", "-")
        .replace("–", "-")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
    )


def _mc(pdf: FPDF, h: float, text: str) -> None:
    """multi_cell with width reset (avoids fpdf2 cursor edge cases after centered title cells)."""
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.w - pdf.r_margin - pdf.l_margin, h, _safe_pdf_text(text))


def build_cve_mapping_pdf(mappings: list[CveTaxonomyMap]) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "NetVision - CVE taxonomy mapping", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(6)

    for m in mappings:
        pdf.set_font("helvetica", "B", 12)
        _mc(pdf, 8, f"CVE: {m.cve_id}")
        pdf.set_font("helvetica", "", 11)
        _mc(pdf, 6, "CWEs: " + ", ".join(m.cwe))
        capec_line = ", ".join(str(c.get("capec_id", "")) for c in m.capec)
        _mc(pdf, 6, "CAPEC: " + capec_line)
        attack_line = ", ".join(
            f"{a.get('id', '')} ({a.get('type', '')})" for a in m.attack if a.get("id") or a.get("name")
        )
        _mc(pdf, 6, "Taxonomies: " + attack_line)
        d3_line = ", ".join(f"{d.get('d3fend_id', '')}" for d in m.d3fend)
        _mc(pdf, 6, "D3FEND: " + d3_line)
        pdf.ln(4)

    return pdf.output()


def build_scan_report_pdf(entry: ScanLogEntry) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "NetVision - Scan report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(4)
    pdf.set_font("helvetica", "", 11)
    _mc(pdf, 6, f"Scan ID: {entry.scan_id}")
    _mc(pdf, 6, f"Time (UTC): {entry.timestamp.isoformat()}")
    _mc(pdf, 6, f"Type: {entry.scan_type.value}  Scanner: {entry.scanner}")
    _mc(pdf, 6, f"Destination: {entry.destination}")
    _mc(pdf, 6, f"Ports touched: {', '.join(str(p) for p in entry.ports)}")
    pdf.ln(4)

    for node in entry.result.graph.nodes:
        if node.id == "scan-origin":
            continue
        pdf.set_font("helvetica", "B", 11)
        _mc(pdf, 7, f"Host {node.ip} - risk {node.risk_level.value}")
        pdf.set_font("helvetica", "", 10)
        ports = ", ".join(str(p) for p in node.open_ports)
        _mc(pdf, 5, f"Open ports: {ports}")
        for svc in node.services[:12]:
            if svc.state != "open":
                continue
            line = f"  {svc.port}/{svc.protocol} {svc.service or ''} {svc.product or ''}"
            _mc(pdf, 5, line)
        pdf.ln(2)

    return pdf.output()


def build_honeypot_pdf(summary: str, lines: list[str]) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(
        0,
        10,
        "NetVision - Honeypot recommendations",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
        align="C",
    )
    pdf.ln(4)
    pdf.set_font("helvetica", "", 11)
    _mc(pdf, 6, summary)
    pdf.ln(2)
    for line in lines:
        _mc(pdf, 6, line)
    return pdf.output()
