import subprocess
from xml.etree import ElementTree as ET

from app.core.config import settings
from app.models.schemas import EdgeData, GraphData, NodeData, RiskLevel, ScanRequest, ScanType, ScannerResult, ServiceInfo
from app.scanners.base import ScannerPlugin


HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900}
MEDIUM_RISK_PORTS = {80, 110, 135, 139, 143, 8080, 8443}
MAX_VULN_ITEMS_PER_HOST = 25
MAX_VULN_OUTPUT_CHARS = 280


def _calculate_risk_level(open_ports: list[int], vuln_hits: int) -> RiskLevel:
    if vuln_hits > 0 or any(port in HIGH_RISK_PORTS for port in open_ports):
        return RiskLevel.red
    if any(port in MEDIUM_RISK_PORTS for port in open_ports):
        return RiskLevel.yellow
    return RiskLevel.green


def parse_nmap_xml(xml_data: str) -> GraphData:
    root = ET.fromstring(xml_data)
    nodes: list[NodeData] = []

    for host in root.findall("host"):
        address_el = host.find("address")
        if address_el is None:
            continue

        ip = address_el.attrib.get("addr", "unknown")
        status_el = host.find("status")
        status = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"

        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hostname_el = hostnames_el.find("hostname")
            if hostname_el is not None:
                hostname = hostname_el.attrib.get("name")

        services: list[ServiceInfo] = []
        open_ports: list[int] = []
        vulnerabilities: list[str] = []

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                port_state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"
                port_num = int(port_el.attrib.get("portid", "0"))
                protocol = port_el.attrib.get("protocol", "tcp")

                if port_state == "open":
                    open_ports.append(port_num)

                service_name = service_el.attrib.get("name") if service_el is not None else None
                product = service_el.attrib.get("product") if service_el is not None else None
                version = service_el.attrib.get("version") if service_el is not None else None

                for script_el in port_el.findall("script"):
                    script_output = script_el.attrib.get("output", "")
                    script_id = script_el.attrib.get("id", "")
                    if "vuln" in script_id.lower() or "cve-" in script_output.lower():
                        cleaned = " ".join(script_output.split())
                        if len(cleaned) > MAX_VULN_OUTPUT_CHARS:
                            cleaned = f"{cleaned[:MAX_VULN_OUTPUT_CHARS]}..."
                        vulnerabilities.append(f"{script_id}: {cleaned}".strip())
                        if len(vulnerabilities) >= MAX_VULN_ITEMS_PER_HOST:
                            vulnerabilities.append("additional vulnerability findings truncated")
                            break

                services.append(
                    ServiceInfo(
                        port=port_num,
                        protocol=protocol,
                        state=port_state,
                        service=service_name,
                        product=product,
                        version=version,
                    )
                )

        risk = _calculate_risk_level(open_ports, len(vulnerabilities))
        node = NodeData(
            id=ip,
            label=hostname or ip,
            ip=ip,
            hostname=hostname,
            status=status,
            risk_level=risk,
            open_ports=sorted(open_ports),
            services=services,
            vulnerabilities=vulnerabilities,
        )
        nodes.append(node)

    # Lightweight topology relation for graph UX until route tracing is added.
    gateway = NodeData(
        id="scan-origin",
        label="Scan Origin",
        ip="0.0.0.0",
        status="up",
        risk_level=RiskLevel.green,
    )
    edges = [
        EdgeData(source=gateway.id, target=node.id, relation="discovered") for node in nodes
    ]

    return GraphData(nodes=[gateway, *nodes], edges=edges)


class NmapScanner(ScannerPlugin):
    name = "nmap"
    description = "Nmap scanner plugin supporting SYN, full, and vuln scans."
    supported_scan_types = [ScanType.syn, ScanType.full, ScanType.vuln]

    def _scan_flags(self, scan_type: ScanType) -> list[str]:
        if scan_type == ScanType.syn:
            return ["-sS", "-T4"]
        if scan_type == ScanType.full:
            return ["-sS", "-sV", "-O", "-T4"]
        if scan_type == ScanType.vuln:
            return ["-sV", "--script", "vuln", "-T4"]
        raise ValueError(f"Unsupported scan type: {scan_type}")

    def build_command(self, request: ScanRequest) -> list[str]:
        return [
            settings.nmap_binary,
            *self._scan_flags(request.scan_type),
            *request.extra_args,
            request.target,
            "-oX",
            "-",
        ]

    def run(self, request: ScanRequest) -> ScannerResult:
        cmd = self.build_command(request)
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=settings.default_scan_timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Nmap binary not found: '{settings.nmap_binary}'. Install nmap or update NETVISION_NMAP_BINARY."
            ) from exc
        if proc.returncode != 0:
            detail = proc.stderr.strip() or "Unknown nmap error"
            raise RuntimeError(f"Nmap scan failed: {detail}")

        graph = parse_nmap_xml(proc.stdout)
        return ScannerResult(
            raw_summary=f"Scanned {request.target} using {request.scan_type.value}",
            graph=graph,
            metadata={"command": " ".join(cmd)},
        )
