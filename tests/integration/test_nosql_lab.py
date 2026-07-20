"""Test de integración end-to-end para detección de NoSQL injection.

Levanta una app Express + MongoDB real, deliberadamente vulnerable al
bypass clásico $ne en autenticación (el vector documentado por
OWASP/PortSwigger: Express usa la librería `qs`, que convierte
'password[$ne]=x' en {password: {$ne: 'x'}} automáticamente). Corre
el pipeline completo de inyector con --nosql --no-sqlmap (sqlmap no
soporta NoSQL) y confirma que la detección de operator injection
funciona de punta a punta, no solo a nivel de unit test.
"""

import json
import os
import subprocess
import time

import pytest

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
COMPOSE_TEST_FILE = os.path.join(FIXTURES_DIR, "docker-compose.test-nosql.yml")
TARGET_URL = "http://localhost:18081/login?username=admin&password=wrong"


def _docker_available() -> bool:
    try:
        subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10, check=True,
        )
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker no disponible — se salta el test de integración",
)


@pytest.fixture(scope="module")
def nosql_lab():
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_TEST_FILE, "up", "-d", "--build"],
        cwd=FIXTURES_DIR, check=True, timeout=180,
    )
    try:
        _wait_for_target("http://localhost:18081/search?q=Widget", timeout=60)
        yield
    finally:
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_TEST_FILE, "down", "-v"],
            cwd=FIXTURES_DIR, check=False, timeout=60,
        )


def _wait_for_target(url: str, timeout: int) -> None:
    import urllib.request

    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return
        except Exception as e:
            last_error = e
            time.sleep(2)
    raise RuntimeError(f"Target de prueba nunca respondió: {last_error}")


def test_detects_real_nosql_operator_injection(nosql_lab):
    reports_dir = os.path.join(REPO_ROOT, "reports")
    before = set(os.listdir(reports_dir)) if os.path.isdir(reports_dir) else set()

    subprocess.run(
        [
            "docker", "compose", "run", "--rm", "inyector",
            "scan", "-u", TARGET_URL, "-p", "password",
            "--nosql", "--no-sqlmap", "--format", "json",
        ],
        cwd=REPO_ROOT, check=True, timeout=90,
    )

    after = set(os.listdir(reports_dir))
    new_files = [f for f in (after - before) if f.endswith(".json")]
    assert new_files, "No se generó ningún reporte JSON nuevo"

    report_path = os.path.join(reports_dir, sorted(new_files)[-1])
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    try:
        nosqli = report["reconnaissance"]["nosqli"]
        assert nosqli["operator_injection"]["vulnerable"] is True, (
            "El lab es deliberadamente vulnerable a bypass $ne — "
            "no detectarlo indica una regresión real"
        )
        assert report["severity"]["level"] != "LIMPIO", (
            "Una NoSQLi confirmada no debería reportarse como LIMPIO "
            "solo porque sqlmap (que no soporta NoSQL) no corrió"
        )
    finally:
        os.remove(report_path)
