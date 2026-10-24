"""ZDG Patch Intelligence API: los KBs más importantes de Windows desde MSRC."""

import logging
import re
import time
from collections import defaultdict
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

MSRC_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0"
CACHE_TTL_SECONDS = 3600  # el documento CVRF pesa varios MB

SYSTEM_PATTERNS = (
    (re.compile(r"Windows 11 Version (\w+)"), "Windows 11 {}"),
    (re.compile(r"Windows 10 Version (\w+)"), "Windows 10 {}"),
    (re.compile(r"Windows Server (\d{4}(?: R2)?)"), "Windows Server {}"),
)
KB_PATTERN = re.compile(r"(?:KB)?(\d{6,7})\b")

logger = logging.getLogger("zdg")

session = requests.Session()
session.headers.update({"Accept": "application/json"})

_cache: dict[str, Any] = {"ts": 0.0, "data": None}

app = FastAPI(
    title="ZDG Patch Intelligence API",
    description="KBs más importantes de Windows según MSRC",
    version="2.3.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


def msrc_get(path: str, timeout: int) -> dict:
    response = session.get(f"{MSRC_BASE_URL}{path}", timeout=timeout)
    response.raise_for_status()
    return response.json()


def get_latest_release() -> dict:
    releases = msrc_get("/updates", timeout=15).get("value", [])
    if not releases:
        raise ValueError("MSRC no devolvió boletines")
    return max(releases, key=lambda r: r.get("InitialReleaseDate", ""))


def collect_products(node: Any, products: dict[str, str]) -> None:
    """Recorre el ProductTree y arma {ProductID: nombre}."""
    if isinstance(node, dict):
        product_id, name = node.get("ProductID"), node.get("Value")
        if isinstance(product_id, str) and isinstance(name, str):
            products[product_id] = name
        for value in node.values():
            collect_products(value, products)
    elif isinstance(node, list):
        for item in node:
            collect_products(item, products)


def classify_system(product_name: str) -> str | None:
    # Solo el SO: descarta ".NET on Windows 11...", Office, Edge, etc.
    if not product_name.startswith("Windows"):
        return None
    for pattern, template in SYSTEM_PATTERNS:
        match = pattern.search(product_name)
        if match:
            return template.format(match.group(1))
    return None


def extract_kb(remediation: dict) -> str | None:
    candidates = (remediation.get("Description", {}).get("Value", ""), remediation.get("URL", ""))
    for text in candidates:
        match = KB_PATTERN.search(str(text))
        if match:
            return f"KB{match.group(1)}"
    return None


def vuln_risk(vuln: dict) -> dict:
    """Riesgo de una CVE: explotada activamente, crítica y CVSS máximo."""
    exploited, critical = False, False
    for threat in vuln.get("Threats", []):
        value = threat.get("Description", {}).get("Value", "")
        if threat.get("Type") == 1 and "Exploited:Yes" in value:
            exploited = True
        elif threat.get("Type") == 3 and value == "Critical":
            critical = True
    scores = [s.get("BaseScore", 0) for s in vuln.get("CVSSScoreSets", [])]
    return {"exploited": exploited, "critical": critical, "cvss": max(scores, default=0)}


def priority(exploited: int, critical: int, max_cvss: float) -> str:
    if exploited:
        return "critica"
    if critical or max_cvss >= 9:
        return "alta"
    return "media"


def build_patches(cvrf: dict, release_id: str, release_date: str) -> list[dict]:
    products: dict[str, str] = {}
    collect_products(cvrf.get("ProductTree", {}), products)

    # (kb, sistema) -> {cve: riesgo}
    cves_by_kb_system: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    builds_by_kb: dict[str, set[str]] = defaultdict(set)

    for vuln in cvrf.get("Vulnerability", []):
        cve = vuln.get("CVE")
        if not cve:
            continue
        risk = vuln_risk(vuln)
        for remediation in vuln.get("Remediations", []):
            kb = extract_kb(remediation)
            if not kb:
                continue
            for product_id in remediation.get("ProductID", []):
                system = classify_system(products.get(product_id, ""))
                if not system:
                    continue
                cves_by_kb_system[(kb, system)][cve] = risk
                if remediation.get("FixedBuild"):
                    builds_by_kb[kb].add(remediation["FixedBuild"])

    # El KB principal de cada sistema es el que corrige más CVEs
    primary: dict[str, tuple[str, int]] = {}
    for (kb, system), cves in cves_by_kb_system.items():
        if system not in primary or len(cves) > primary[system][1]:
            primary[system] = (kb, len(cves))

    grouped: dict[str, dict] = defaultdict(lambda: {"sistemas": set(), "cves": {}})
    for system, (kb, _) in primary.items():
        grouped[kb]["sistemas"].add(system)
        grouped[kb]["cves"].update(cves_by_kb_system[(kb, system)])

    patches = []
    for kb, entry in grouped.items():
        risks = entry["cves"].values()
        exploited = sum(r["exploited"] for r in risks)
        critical = sum(r["critical"] for r in risks)
        max_cvss = max((r["cvss"] for r in risks), default=0)
        patches.append(
            {
                "kb": kb,
                "sistemas": sorted(entry["sistemas"]),
                "prioridad": priority(exploited, critical, max_cvss),
                "cves_corregidas": len(entry["cves"]),
                "cves_explotadas": exploited,
                "cves_criticas": critical,
                "cvss_maximo": max_cvss,
                "fixed_builds": sorted(builds_by_kb[kb]),
                "fecha_lanzamiento": release_date,
                "boletin_oficial": release_id,
            }
        )

    return sorted(patches, key=lambda p: (p["cves_explotadas"], p["cvss_maximo"]), reverse=True)


def fetch_patch_data() -> dict:
    release = get_latest_release()
    release_id = release["ID"]
    release_date = release.get("InitialReleaseDate", "")[:10]

    cvrf = msrc_get(f"/cvrf/{release_id}", timeout=60)
    return {
        "status": "success",
        "fuente": "Microsoft Security Response Center (MSRC)",
        "boletin_mes": release_id,
        "parches": build_patches(cvrf, release_id, release_date),
    }


def get_patch_data() -> dict:
    cached = _cache["data"]
    if cached and time.time() - _cache["ts"] < CACHE_TTL_SECONDS:
        return cached

    try:
        data = fetch_patch_data()
    except (requests.RequestException, KeyError, ValueError) as exc:
        logger.error("Error consultando MSRC: %s", exc)
        if cached:
            return {**cached, "status": "stale"}
        raise HTTPException(status_code=502, detail="No se pudo consultar MSRC")

    _cache.update(ts=time.time(), data=data)
    return data


@app.get("/api/v1/latest-kbs")
def latest_kbs(limit: int = Query(10, ge=1, le=50)) -> dict:
    data = get_patch_data()
    patches = data["parches"][:limit]
    return {**data, "total_parches": len(patches), "parches": patches}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)