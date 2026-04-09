from fastapi import APIRouter, HTTPException, status

from app.models.schemas import HoneypotAnalyzeRequest, HoneypotAnalyzeResponse
from app.services.honeypot_service import analyze_topology
from app.services.log_service import log_service

router = APIRouter(prefix="/honeypot", tags=["honeypot"])


@router.post("/analyze", response_model=HoneypotAnalyzeResponse)
def analyze_honeypot_placements(body: HoneypotAnalyzeRequest) -> HoneypotAnalyzeResponse:
    if body.graph is not None:
        return analyze_topology(body.graph)

    if body.scan_id:
        entry = log_service.get_log(body.scan_id)
        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan log not found",
            )
        return analyze_topology(entry.result.graph)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Provide either scan_id or graph",
    )
