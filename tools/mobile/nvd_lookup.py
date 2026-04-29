#!/usr/bin/env python3
"""
Real-time NVD (National Vulnerability Database) CVE lookup utility.
Uses NVD REST API v2: https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limits: 5 req/30s without API key, 50 req/30s with NVDAPIKEY env var.
"""

import re
import time
import json
from typing import List, Dict, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE: Dict[str, Dict] = {}
_LAST_REQUEST_TIME = 0.0
_REQUEST_DELAY = 6.5  # seconds between requests (conservative for no-key rate limit)


def _nvd_get(params: dict, api_key: str = "") -> Optional[Dict]:
    """Make a rate-limited GET to NVD API v2, return parsed JSON or None"""
    global _LAST_REQUEST_TIME
    if not _HAS_REQUESTS:
        return None
    # Respect rate limit
    elapsed = time.time() - _LAST_REQUEST_TIME
    if elapsed < _REQUEST_DELAY:
        time.sleep(_REQUEST_DELAY - elapsed)
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(NVD_BASE, params=params, headers=headers,
                         timeout=10, verify=True)
        _LAST_REQUEST_TIME = time.time()
        if r.status_code == 200:
            return r.json()
        if r.status_code == 403:
            # API key required / rate limited
            time.sleep(30)
        return None
    except Exception:
        return None


def lookup_cve(cve_id: str, api_key: str = "") -> Optional[Dict]:
    """
    Fetch a single CVE from NVD by ID.
    Returns simplified dict: {id, description, cvss_v3, cvss_v2, severity, references, published}
    """
    cve_id = cve_id.upper().strip()
    if cve_id in _CACHE:
        return _CACHE[cve_id]

    data = _nvd_get({"cveId": cve_id}, api_key)
    if not data:
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    item   = vulns[0].get("cve", {})
    cve_id = item.get("id", cve_id)

    # Description (English preferred)
    desc = ""
    for d in item.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS scores
    metrics  = item.get("metrics", {})
    cvss_v3  = 0.0
    cvss_v2  = 0.0
    severity = "UNKNOWN"
    v31_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if v31_data:
        cv = v31_data[0].get("cvssData", {})
        cvss_v3  = cv.get("baseScore", 0.0)
        severity = cv.get("baseSeverity", "UNKNOWN")
    v2_data = metrics.get("cvssMetricV2", [])
    if v2_data:
        cvss_v2 = v2_data[0].get("cvssData", {}).get("baseScore", 0.0)

    # References
    refs = [r.get("url", "") for r in item.get("references", [])[:5]]

    result = {
        "id":          cve_id,
        "description": desc[:400],
        "cvss_v3":     cvss_v3,
        "cvss_v2":     cvss_v2,
        "severity":    severity,
        "references":  refs,
        "published":   item.get("published", ""),
        "modified":    item.get("lastModified", ""),
    }
    _CACHE[cve_id] = result
    return result


def search_cves_by_keyword(keyword: str, results: int = 5,
                           api_key: str = "") -> List[Dict]:
    """
    Search NVD for CVEs matching a keyword (e.g. 'android bluetooth').
    Returns list of simplified CVE dicts, sorted by CVSS score desc.
    """
    cache_key = f"kw:{keyword}:{results}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    data = _nvd_get({
        "keywordSearch": keyword,
        "resultsPerPage": min(results, 20),
    }, api_key)
    if not data:
        return []

    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_v3 = 0.0
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30"):
            lst = metrics.get(key, [])
            if lst:
                cv = lst[0].get("cvssData", {})
                cvss_v3  = cv.get("baseScore", 0.0)
                severity = cv.get("baseSeverity", "UNKNOWN")
                break
        out.append({
            "id":          cid,
            "description": desc[:300],
            "cvss_v3":     cvss_v3,
            "severity":    severity,
            "published":   cve.get("published", ""),
        })

    out.sort(key=lambda x: -x["cvss_v3"])
    _CACHE[cache_key] = out
    return out


def enrich_cve_list(cve_ids: List[str], api_key: str = "") -> List[Dict]:
    """
    Enrich a list of CVE IDs with real NVD data.
    Skips IDs already in cache; respects rate limits.
    Returns list of enriched dicts.
    """
    enriched = []
    for cid in cve_ids:
        result = lookup_cve(cid, api_key)
        if result:
            enriched.append(result)
    return enriched


if __name__ == "__main__":
    # Quick CLI test
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 nvd_lookup.py CVE-2024-0044")
        sys.exit(1)
    r = lookup_cve(sys.argv[1])
    print(json.dumps(r, indent=2))
