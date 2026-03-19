# Cybersecurity MCP Server 🔒

CVE database and vulnerability intelligence for AI agents. Search the NIST National Vulnerability Database, check software security, and stay informed about threats.

## Features

- **CVE Search** — Search vulnerabilities by keyword or severity
- **CVE Details** — Full details including CVSS score, affected products, references
- **Software Check** — Check any software for known vulnerabilities
- **CPE Database** — Search products in the Common Platform Enumeration
- **No API Key** — Uses the free NIST NVD API

## Installation

```bash
pip install cybersecurity-mcp-server
```

## Tools

| Tool | Description |
|------|-------------|
| `search_vulnerabilities` | Search CVE database by keyword |
| `get_cve_details` | Get full CVE details by ID |
| `check_software_vulnerabilities` | Check a software for known CVEs |
| `search_products` | Search CPE product database |

## Examples

```
"Are there critical vulnerabilities in Apache Log4j?"
"Show me CVE-2021-44228 details"
"Check nginx for known security issues"
"What are the latest critical CVEs?"
```

## License

MIT
