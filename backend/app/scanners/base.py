from abc import ABC, abstractmethod

from app.models.schemas import ScanRequest, ScanType, ScannerResult


class ScannerPlugin(ABC):
    name: str
    description: str
    supported_scan_types: list[ScanType]

    @abstractmethod
    def run(self, request: ScanRequest) -> ScannerResult:
        raise NotImplementedError
