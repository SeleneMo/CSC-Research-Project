from app.models.schemas import SCAN_TYPE_LABELS, ScannerDescriptor
from app.scanners.base import ScannerPlugin


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, ScannerPlugin] = {}

    def register(self, scanner: ScannerPlugin) -> None:
        self._scanners[scanner.name] = scanner

    def get(self, scanner_name: str) -> ScannerPlugin:
        scanner = self._scanners.get(scanner_name)
        if scanner is None:
            available = ", ".join(self._scanners.keys())
            raise ValueError(f"Unknown scanner '{scanner_name}'. Available: {available}")
        return scanner

    def list_scanners(self) -> list[ScannerDescriptor]:
        return [
            ScannerDescriptor(
                name=scanner.name,
                supported_scan_types=scanner.supported_scan_types,
                scan_type_labels={
                    st.value: SCAN_TYPE_LABELS.get(st, st.value.replace("_", " ").title())
                    for st in scanner.supported_scan_types
                },
                description=scanner.description,
            )
            for scanner in self._scanners.values()
        ]


registry = ScannerRegistry()

from app.scanners.plugins import register_builtin_scanners  # noqa: E402

register_builtin_scanners(registry)
