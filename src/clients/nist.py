"""NIST NVD API Client — CVE-Datenbank und Vulnerability-Suche."""

import httpx


class NistClient:
    """Async-Client für die NIST National Vulnerability Database."""

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=30.0)
        self._base = "https://services.nvd.nist.gov/rest/json"

    async def search_cves(
        self, keyword: str = None, cve_id: str = None,
        severity: str = None, limit: int = 10,
    ) -> dict:
        """CVEs suchen über die NVD API 2.0."""
        url = f"{self._base}/cves/2.0"
        params = {"resultsPerPage": min(limit, 50)}

        if cve_id:
            params["cveId"] = cve_id
        if keyword:
            params["keywordSearch"] = keyword
        if severity:
            params["cvssV3Severity"] = severity.upper()

        resp = await self._client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_cve(self, cve_id: str) -> dict:
        """Einzelne CVE-Details abrufen."""
        url = f"{self._base}/cves/2.0"
        params = {"cveId": cve_id}
        resp = await self._client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def search_cpes(self, keyword: str, limit: int = 10) -> dict:
        """CPE (Common Platform Enumeration) suchen — Software/Hardware identifizieren."""
        url = f"{self._base}/cpes/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 50)}
        resp = await self._client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()
