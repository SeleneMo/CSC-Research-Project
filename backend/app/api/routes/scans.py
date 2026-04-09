from fastapi import APIRouter, HTTPException, status

from app.models.schemas import RunScanResponse, ScanLogEntry, ScanRequest, ScannerDescriptor
from app.services.log_service import log_service
from app.services.scanner_registry import registry

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/plugins", response_model=list[ScannerDescriptor])
def list_plugins() -> list[ScannerDescriptor]:
    return registry.list_scanners()


@router.post("/run", response_model=RunScanResponse, status_code=status.HTTP_201_CREATED)
def run_scan(request: ScanRequest) -> RunScanResponse:
    try:
        scanner = registry.get(request.scanner)
        result = scanner.run(request)
        log_entry = log_service.write_log(request, result)
        return RunScanResponse(scan=log_entry)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.get("/logs", response_model=list[ScanLogEntry])
def get_scan_logs() -> list[ScanLogEntry]:
    return log_service.list_logs()


@router.get("/logs/{scan_id}", response_model=ScanLogEntry)
def get_scan_log(scan_id: str) -> ScanLogEntry:
    entry = log_service.get_log(scan_id)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan log not found")
    return entry


@router.get("/replay/{scan_id}", response_model=ScanLogEntry)
def replay_scan(scan_id: str) -> ScanLogEntry:
    entry = log_service.get_log(scan_id)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan log not found")
    return entry
