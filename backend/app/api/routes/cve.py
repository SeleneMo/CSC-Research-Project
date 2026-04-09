import csv
import io

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.models.schemas import CveMapRequest, CveMapResponse
from app.services import cve_mapper

router = APIRouter(prefix="/cve", tags=["cve"])


@router.post("/map", response_model=CveMapResponse)
def map_cves(body: CveMapRequest) -> CveMapResponse:
    return cve_mapper.map_cve_batch(body.cve_ids)


@router.post("/map/csv", response_model=CveMapResponse)
async def map_cves_csv(file: UploadFile = File(...)) -> CveMapResponse:
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "cveID" not in reader.fieldnames:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV must include a 'cveID' column (first column in template).",
        )

    ids: list[str] = []
    for row in reader:
        cell = (row.get("cveID") or "").strip()
        if cell:
            ids.append(cell)

    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No CVE IDs found in CSV.",
        )

    return cve_mapper.map_cve_batch(ids)
