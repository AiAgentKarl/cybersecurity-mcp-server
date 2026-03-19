"""Cybersecurity MCP Server — CVE-Datenbank und Vulnerability-Intelligence."""

from mcp.server.fastmcp import FastMCP
from src.tools.security import register_security_tools

mcp = FastMCP(
    "Cybersecurity MCP Server",
    instructions="Search CVE vulnerabilities, check software security, browse the NIST National Vulnerability Database. Essential for any agent working with code or infrastructure.",
)
register_security_tools(mcp)

def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
