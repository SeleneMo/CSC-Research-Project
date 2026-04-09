"""Placeholder scanner for UI tests without Nmap installed."""

from app.models.schemas import EdgeData, GraphData, NodeData, RiskLevel, ScanRequest, ScanType, ScannerResult, ServiceInfo
from app.scanners.base import ScannerPlugin


class StubScanner(ScannerPlugin):
    name = "stub"
    description = "Returns a synthetic graph (no network I/O). Use for frontend and API tests."
    supported_scan_types = [ScanType.syn, ScanType.full, ScanType.vuln]

    def run(self, request: ScanRequest) -> ScannerResult:
        demo = NodeData(
            id="192.0.2.10",
            label="demo-host",
            ip="192.0.2.10",
            hostname="demo-host",
            status="up",
            risk_level=RiskLevel.yellow,
            open_ports=[22, 80],
            services=[
                ServiceInfo(port=22, protocol="tcp", state="open", service="ssh"),
                ServiceInfo(port=80, protocol="tcp", state="open", service="http"),
            ],
            vulnerabilities=[],
        )
        origin = NodeData(
            id="scan-origin",
            label="Scan Origin",
            ip="0.0.0.0",
            status="up",
            risk_level=RiskLevel.green,
        )
        graph = GraphData(
            nodes=[origin, demo],
            edges=[EdgeData(source=origin.id, target=demo.id, relation="discovered")],
        )
        return ScannerResult(
            raw_summary=f"Stub scan for target {request.target!r} ({request.scan_type.value})",
            graph=graph,
            metadata={"stub": True, "scanner": self.name},
        )
