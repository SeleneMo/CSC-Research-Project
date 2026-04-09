"""
Central registration for scanner plugins (Nmap, Nikto, custom tools).

To add a new scanning tool:
  1. Create ``your_tool_scanner.py`` with a class extending ``ScannerPlugin``
     (see ``plugin_template.py`` and ``nmap_scanner.py``).
  2. Implement ``name``, ``description``, ``supported_scan_types``, and ``run()``.
  3. Import the class here and call ``registry.register(YourScanner())`` below.

Optional: if the tool can stream progress lines, extend the WebSocket handler in
``app.api.routes.scan_stream`` (currently streams Nmap stderr for ``scanner=="nmap"``).
"""


def register_builtin_scanners(registry) -> None:
    from app.scanners.nmap_scanner import NmapScanner
    from app.scanners.stub_scanner import StubScanner

    registry.register(NmapScanner())
    registry.register(StubScanner())

    # Example — when you implement a Nikto (or other) adapter:
    # from app.scanners.nikto_scanner import NiktoScanner
    # registry.register(NiktoScanner())
