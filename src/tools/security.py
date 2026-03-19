"""Security-Tools — CVE-Suche, Vulnerability-Analyse, Threat Intelligence."""

from mcp.server.fastmcp import FastMCP
from src.clients.nist import NistClient

_nist = NistClient()


def _parse_cve(item: dict) -> dict:
    """CVE-Eintrag in lesbares Format umwandeln."""
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})

    # CVSS Score extrahieren
    cvss_score = None
    cvss_severity = None
    cvss_vector = None

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            cvss_data = metrics[version][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break

    # Beschreibung (englisch bevorzugt)
    descriptions = cve.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # Betroffene Produkte
    configs = cve.get("configurations", [])
    affected = []
    for config in configs[:3]:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", [])[:5]:
                affected.append(match.get("criteria", ""))

    # Referenzen
    refs = [r.get("url") for r in cve.get("references", [])[:5]]

    return {
        "cve_id": cve.get("id", ""),
        "description": desc[:500],
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "affected_products": affected[:5],
        "references": refs,
        "status": cve.get("vulnStatus", ""),
    }


def register_security_tools(mcp: FastMCP):

    @mcp.tool()
    async def search_vulnerabilities(
        keyword: str, severity: str = None, limit: int = 10,
    ) -> dict:
        """CVE-Datenbank nach Schwachstellen durchsuchen.

        Durchsucht die NIST National Vulnerability Database (NVD).

        Args:
            keyword: Suchbegriff (z.B. "Apache Log4j", "OpenSSL", "Windows RDP")
            severity: Optional — "LOW", "MEDIUM", "HIGH", "CRITICAL"
            limit: Maximale Ergebnisse (Standard: 10)
        """
        data = await _nist.search_cves(keyword=keyword, severity=severity, limit=limit)
        vulnerabilities = data.get("vulnerabilities", [])
        return {
            "query": keyword,
            "total_results": data.get("totalResults", 0),
            "results_count": len(vulnerabilities),
            "vulnerabilities": [_parse_cve(v) for v in vulnerabilities],
        }

    @mcp.tool()
    async def get_cve_details(cve_id: str) -> dict:
        """Details einer bestimmten CVE abrufen.

        Args:
            cve_id: CVE-ID (z.B. "CVE-2021-44228" für Log4Shell)
        """
        data = await _nist.get_cve(cve_id)
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            return _parse_cve(vulnerabilities[0])
        return {"found": False, "cve_id": cve_id}

    @mcp.tool()
    async def check_software_vulnerabilities(software: str, limit: int = 10) -> dict:
        """Bekannte Schwachstellen für eine Software prüfen.

        Sucht nach CVEs die eine bestimmte Software betreffen.

        Args:
            software: Software-Name (z.B. "nginx", "postgresql", "react")
            limit: Maximale Ergebnisse
        """
        data = await _nist.search_cves(keyword=software, limit=limit)
        vulnerabilities = data.get("vulnerabilities", [])
        parsed = [_parse_cve(v) for v in vulnerabilities]

        # Nach Schweregrad sortieren
        parsed.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)

        critical = sum(1 for v in parsed if (v.get("cvss_score") or 0) >= 9.0)
        high = sum(1 for v in parsed if 7.0 <= (v.get("cvss_score") or 0) < 9.0)

        return {
            "software": software,
            "total_found": data.get("totalResults", 0),
            "critical_count": critical,
            "high_count": high,
            "vulnerabilities": parsed,
        }

    @mcp.tool()
    async def search_products(keyword: str, limit: int = 10) -> dict:
        """Software/Hardware-Produkte in der CPE-Datenbank suchen.

        CPE (Common Platform Enumeration) identifiziert Produkte eindeutig.

        Args:
            keyword: Produkt-Name (z.B. "microsoft windows", "apache httpd")
            limit: Maximale Ergebnisse
        """
        data = await _nist.search_cpes(keyword, limit)
        products = data.get("products", [])
        parsed = []
        for p in products:
            cpe = p.get("cpe", {})
            parsed.append({
                "cpe_name": cpe.get("cpeName", ""),
                "title": cpe.get("titles", [{}])[0].get("title", "") if cpe.get("titles") else "",
                "created": cpe.get("created", ""),
                "deprecated": cpe.get("deprecated", False),
            })
        return {
            "query": keyword,
            "total_results": data.get("totalResults", 0),
            "products": parsed,
        }
