from fastapi import APIRouter, HTTPException, Response, status

from app.models.schemas import CveMapRequest, CveMappingsPdfRequest
from app.services import cve_mapper
from app.services.honeypot_service import analyze_topology
from app.services.log_service import log_service
from app.services.report_service import (
    build_cve_mapping_pdf,
    build_honeypot_pdf,
    build_scan_report_pdf,
)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/scan/{scan_id}/pdf")
def download_scan_pdf(scan_id: str) -> Response:
    entry = log_service.get_log(scan_id)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    data = bytes(build_scan_report_pdf(entry))
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="netvision-scan-{scan_id}.pdf"'},
    )


@router.post("/cve/pdf")
def download_cve_pdf(body: CveMapRequest) -> Response:
    mapped = cve_mapper.map_cve_batch(body.cve_ids)
    data = bytes(build_cve_mapping_pdf(mapped.mappings))
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=netvision-cve-mappings.pdf"},
    )


@router.get("/honeypot/{scan_id}/pdf")
def download_honeypot_from_scan_pdf(scan_id: str) -> Response:
    entry = log_service.get_log(scan_id)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    analysis = analyze_topology(entry.result.graph)
    lines = [
        f"P{rec.priority}: {rec.ip} — {rec.rationale} Ports: {rec.emulate_ports}"
        for rec in analysis.recommendations
    ]
    data = bytes(build_honeypot_pdf(analysis.summary, lines))
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="netvision-honeypot-{scan_id}.pdf"'
        },
    )


@router.post("/cve/mapping-pdf")
def download_cve_pdf_from_payload(body: CveMappingsPdfRequest) -> Response:
    """PDF from mappings already returned by POST /cve/map (avoids duplicate NVD lookups)."""
    data = bytes(build_cve_mapping_pdf(body.mappings))
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=netvision-cve-mappings.pdf"},
    )
