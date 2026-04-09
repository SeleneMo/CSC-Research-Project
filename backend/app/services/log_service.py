import json
from datetime import datetime, UTC
from pathlib import Path
from uuid import uuid4

from app.core.config import settings
from app.models.schemas import ScanLogEntry, ScanRequest, ScannerResult


class ScanLogService:
    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path or settings.scan_log_file
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

    def write_log(self, request: ScanRequest, result: ScannerResult) -> ScanLogEntry:
        ports = sorted({port for node in result.graph.nodes for port in node.open_ports})
        entry = ScanLogEntry(
            scan_id=str(uuid4()),
            timestamp=datetime.now(UTC),
            scanner=request.scanner,
            scan_type=request.scan_type,
            source=request.source,
            destination=request.target,
            ports=ports,
            result=result,
        )
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.model_dump_json())
            handle.write("\n")
        return entry

    def list_logs(self) -> list[ScanLogEntry]:
        entries: list[ScanLogEntry] = []
        with self.log_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                entries.append(ScanLogEntry.model_validate(payload))
        return sorted(entries, key=lambda item: item.timestamp, reverse=True)

    def get_log(self, scan_id: str) -> ScanLogEntry | None:
        for entry in self.list_logs():
            if entry.scan_id == scan_id:
                return entry
        return None


log_service = ScanLogService()
