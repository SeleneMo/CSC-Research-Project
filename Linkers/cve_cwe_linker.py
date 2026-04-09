import csv
import logging
import os

import nvdlib

logger = logging.getLogger(__name__)

testCSV = "csv/test.csv"


def _nvd_api_key() -> str | None:
    key = os.environ.get("NETVISION_NVD_API_KEY", "").strip()
    return key or None


def search_nvd(cve_id: str) -> None:
    kwargs: dict = {"cveId": cve_id, "delay": 0.6}
    api_key = _nvd_api_key()
    if api_key:
        kwargs["key"] = api_key
    else:
        logger.warning("NETVISION_NVD_API_KEY is not set; NVD requests may be rate-limited.")

    with open(testCSV, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        try:
            results = nvdlib.searchCVE(**kwargs)
        except Exception as exc:
            logger.exception("NVD lookup failed for %s", cve_id)
            writer.writerow([cve_id, f"NVD error: {exc}"])
            return

        if results:
            cve_entry = results[0]
            if cve_entry.weaknesses:
                cwe_id_array = []
                for weakness_entry in cve_entry.weaknesses:
                    for desc in weakness_entry.description:
                        raw_id = desc.value.split(":")[0].strip()
                        cwe_id_array.append(raw_id)
                cwe_id = "::".join(cwe_id_array)
                writer.writerow([cve_entry.id, cwe_id])
            else:
                logger.info("No direct CWE mapping in NVD for %s", cve_id)
                writer.writerow(
                    [cve_entry.id, "No direct CWE mapping found in the NVD entry."]
                )
        else:
            logger.info("CVE %s not found or no NVD results", cve_id)
            writer.writerow([cve_id, f"CVE ID {cve_id} not found or no results returned."])


def get_cve_cwe_mapping(cve_id: str, _tried_nvd: bool = False) -> list[str]:
    with open("csv/test.csv", "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            if row[0] == cve_id:
                return row[1].split("::")

    if _tried_nvd:
        return []

    search_nvd(cve_id)
    return get_cve_cwe_mapping(cve_id, _tried_nvd=True)
