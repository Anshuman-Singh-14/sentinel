r"""Run Sentinel's own header checker against Sentinel's production front end.

04-security.md section 9: "Sentinel should pass its own header checker".
Runs inside the api container (it has the checker and network access to the
frontend), so nothing is installed on the host:

    docker compose -f docker-compose.yml -f docker-compose.prod.yml \
        exec -T api python - < scripts/self_header_check.py

Exits non-zero if any header finding is above INFO. HSTS is not assessed:
the front end is served over plain HTTP on localhost; put TLS in front of it
(and HSTS with it) for a real deployment.
"""

import sys

import httpx

from app.engine.schemas import Severity
from app.tools.header_tls.translator import _header_findings, header_map

URLS = sys.argv[1:] or ["http://frontend:8080/", "http://frontend:8080/api/v1/tools"]

failed = False
for url in URLS:
    response = httpx.get(url, timeout=10, follow_redirects=False)
    findings = _header_findings(header_map(list(response.headers.items())), False, "sentinel")
    print(f"{url} -> {response.status_code}")
    for finding in findings:
        mark = "ok " if finding.severity is Severity.INFO else "BAD"
        print(f"  [{mark}] {finding.severity.value:<8} {finding.item}")
        failed |= finding.severity is not Severity.INFO
sys.exit(1 if failed else 0)
