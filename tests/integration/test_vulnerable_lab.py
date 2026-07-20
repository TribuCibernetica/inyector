"""Test de integración end-to-end contra un lab real y controlado.

A diferencia de los tests unitarios (que no tocan red ni Docker),
este test levanta una app PHP+MySQL deliberadamente vulnerable (el
mismo patrón que testphp.vulnweb.com: concatenación cruda + error
visible) y corre el pipeline COMPLETO de inyector contra ella:
recon -> inteligencia -> sqlmap -> reporte.

Sirve para agarrar regresiones reales como las que motivaron esta
suite: un cambio que rompa la construcción del comando sqlmap, el
parseo del output, o el manejo de fallos, haría fallar este test
aunque todos los tests unitarios sigan pasando (porque unitariamente
cada pieza seguiría "funcionando", solo que juntas dejarían de
detectar una SQLi real).

Requiere Docker. Se salta automáticamente si el daemon no está
disponible (ej. en un sandbox sin Docker).
"""

import json
import os
import shutil
import subprocess
import time

import pytest

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
COMPOSE_TEST_FILE = os.path.join(FIXTURES_DIR, "docker-compose.test.yml")
TARGET_URL = "http://localhost:18080/?id=1"


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
def vulnerable_lab():
    """Levanta el lab vulnerable y lo tira al terminar."""
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_TEST_FILE, "up", "-d", "--build"],
        cwd=FIXTURES_DIR, check=True, timeout=180,
    )
    try:
        _wait_for_target(TARGET_URL, timeout=60)
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


def test_full_pipeline_detects_real_sqli(vulnerable_lab, tmp_path):
    reports_dir = os.path.join(REPO_ROOT, "reports")
    before = set(os.listdir(reports_dir)) if os.path.isdir(reports_dir) else set()

    subprocess.run(
        [
            "docker", "compose", "run", "--rm", "inyector",
            "scan", "-u", TARGET_URL, "--format", "json",
        ],
        cwd=REPO_ROOT, check=True, timeout=180,
    )

    after = set(os.listdir(reports_dir))
    new_files = [f for f in (after - before) if f.endswith(".json")]
    assert new_files, "No se generó ningún reporte JSON nuevo"

    report_path = os.path.join(reports_dir, sorted(new_files)[-1])
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    try:
        assert report["severity"]["level"] != "LIMPIO", (
            "El lab de prueba es deliberadamente vulnerable — "
            "un resultado LIMPIO indica una regresión real"
        )
        assert len(report["vulnerabilities"]) >= 1
        assert "mysql" in report["dbms"]["name"].lower()
    finally:
        os.remove(report_path)
