"""
Template for a new NetVision scanner plugin (not registered by default).

Steps:
  1. Copy this file to ``my_scanner.py`` (same package).
  2. Set ``name`` to a stable id (e.g. ``"nikto"``) used in API ``scanner`` field.
  3. Map your tool's modes to ``ScanType`` values or extend ``ScanType`` in
     ``app.models.schemas`` if you need custom modes.
  4. Run your CLI/API in ``run()``, then return ``ScannerResult`` with a
     ``GraphData`` graph (nodes + edges) so the React UI can visualize it.
  5. Register in ``app.scanners.plugins.register_builtin_scanners``.
"""

# from subprocess import run
# from app.models.schemas import GraphData, ScanRequest, ScanType, ScannerResult
# from app.scanners.base import ScannerPlugin
#
#
# class MyToolScanner(ScannerPlugin):
#     name = "my_tool"
#     description = "Short description for GET /scans/plugins."
#     supported_scan_types = [ScanType.syn, ScanType.full]
#
#     def run(self, request: ScanRequest) -> ScannerResult:
#         # Example: run(["mytool", "--target", request.target], capture_output=True, timeout=300)
#         graph = GraphData(nodes=[], edges=[])
#         return ScannerResult(raw_summary="...", graph=graph, metadata={})
