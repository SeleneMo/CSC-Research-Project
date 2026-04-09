import asyncio
import queue
import subprocess
import threading

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.core.config import settings
from app.models.schemas import ScanRequest, ScannerResult
from app.scanners.nmap_scanner import NmapScanner, parse_nmap_xml
from app.services.log_service import log_service
from app.services.scanner_registry import registry

router = APIRouter(tags=["scans"])


@router.websocket("/ws/scans")
async def websocket_run_scan(websocket: WebSocket) -> None:
    """Stream nmap stderr lines, then emit parsed scan JSON (same shape as POST /scans/run)."""
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        request = ScanRequest.model_validate(payload)
    except Exception as exc:
        await websocket.send_json({"type": "error", "message": f"Invalid payload: {exc}"})
        await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA)
        return

    try:
        scanner = registry.get(request.scanner)
    except ValueError as exc:
        await websocket.send_json({"type": "error", "message": str(exc)})
        await websocket.close()
        return

    if request.scanner != "nmap" or not isinstance(scanner, NmapScanner):
        try:
            result = await asyncio.to_thread(scanner.run, request)
            log_entry = log_service.write_log(request, result)
            await websocket.send_json(
                {"type": "complete", "scan": log_entry.model_dump(mode="json")}
            )
        except Exception as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
        return

    cmd = scanner.build_command(request)
    sq: queue.Queue = queue.Queue()

    def worker() -> None:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            assert proc.stderr is not None
            assert proc.stdout is not None
            for line in iter(proc.stderr.readline, ""):
                stripped = line.strip()
                if stripped:
                    sq.put(("log", stripped))
            try:
                proc.wait(timeout=settings.default_scan_timeout_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                sq.put(("error", "Nmap scan timed out"))
                return

            xml = proc.stdout.read()
            if proc.returncode != 0:
                sq.put(("error", f"Nmap exited with code {proc.returncode}"))
                return
            if not xml.strip():
                sq.put(("error", "Nmap returned empty XML output"))
                return
            sq.put(("done", xml))
        except FileNotFoundError:
            sq.put(
                (
                    "error",
                    f"Nmap binary not found: '{settings.nmap_binary}'. "
                    "Install nmap or set NETVISION_NMAP_BINARY.",
                )
            )
        except Exception as exc:
            sq.put(("error", str(exc)))

    threading.Thread(target=worker, daemon=True).start()

    try:
        while True:
            kind, *rest = await asyncio.to_thread(sq.get)
            if kind == "log":
                await websocket.send_json({"type": "log", "message": rest[0]})
            elif kind == "error":
                await websocket.send_json({"type": "error", "message": rest[0]})
                return
            elif kind == "done":
                xml = rest[0]
                break
            else:
                await websocket.send_json({"type": "error", "message": "Internal stream error"})
                return

        graph = parse_nmap_xml(xml)
        result = ScannerResult(
            raw_summary=f"Scanned {request.target} using {request.scan_type.value} (streamed)",
            graph=graph,
            metadata={"command": " ".join(cmd)},
        )
        log_entry = log_service.write_log(request, result)
        await websocket.send_json({"type": "complete", "scan": log_entry.model_dump(mode="json")})
    except WebSocketDisconnect:
        return
