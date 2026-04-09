import json
import os
import re
import threading
from contextlib import contextmanager

from app.core.config import settings
from app.models.schemas import CveMapResponse, CveTaxonomyMap

_linker_lock = threading.Lock()
_import_lock = threading.Lock()
_imports_ready = False


def _ensure_imports() -> None:
    global _imports_ready
    with _import_lock:
        if _imports_ready:
            return
        import sys

        root = str(settings.project_root)
        if root not in sys.path:
            sys.path.insert(0, root)
        _imports_ready = True


@contextmanager
def _project_cwd():
    with _linker_lock:
        prev = os.getcwd()
        os.chdir(settings.project_root)
        try:
            yield
        finally:
            os.chdir(prev)


def _usable_cwe(cwes: list[str]) -> bool:
    blob = " ".join(cwes).lower()
    if "error" in blob or "not found" in blob or "no direct cwe" in blob:
        return False
    return any(re.search(r"CWE-?\d+", c, re.I) for c in cwes)


def map_cve_id(cve_id: str) -> CveTaxonomyMap:
    _ensure_imports()
    from Linkers import attack_defend_linker
    from Linkers import capec_taxonomy_linker
    from Linkers import cve_cwe_linker
    from Linkers import cwe_capec_linker

    cve_id = cve_id.strip()
    with _project_cwd():
        cwe = cve_cwe_linker.get_cve_cwe_mapping(cve_id)
        if not _usable_cwe(cwe):
            return CveTaxonomyMap(cve_id=cve_id, cwe=cwe, capec=[], attack=[], d3fend=[])

        capec = cwe_capec_linker.get_cwe_capec_mapping(cwe)
        attack = capec_taxonomy_linker.get_capec_attack_mapping([c["capec_id"] for c in capec])
        attack_ids = [a["id"] for a in attack if a.get("type") == "ATT&CK" and a.get("id")]
        d3fend = attack_defend_linker.get_attack_defend_mapping(attack_ids)

    return CveTaxonomyMap(
        cve_id=cve_id,
        cwe=cwe,
        capec=capec,
        attack=attack,
        d3fend=d3fend,
    )


def map_cve_batch(cve_ids: list[str]) -> CveMapResponse:
    unique: list[str] = []
    seen: set[str] = set()
    for cid in cve_ids:
        c = cid.strip()
        if c and c not in seen:
            seen.add(c)
            unique.append(c)
    mappings = [map_cve_id(cid) for cid in unique]
    _append_cve_log(mappings)
    return CveMapResponse(mappings=mappings)


def _append_cve_log(mappings: list[CveTaxonomyMap]) -> None:
    path = settings.cve_mapping_log_file
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for m in mappings:
            handle.write(json.dumps(m.model_dump(), default=str))
            handle.write("\n")
