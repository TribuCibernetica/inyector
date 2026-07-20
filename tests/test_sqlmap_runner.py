"""Tests para SqlmapRunner._detect_failure_reason.

Regresión del bug: sqlmap puede terminar con exit code 0 aunque nunca
haya llegado a probar la inyección (target inalcanzable, etc). Antes
esto se reportaba exactamente igual que un 'no vulnerable' legítimo.
"""

from inyector.executor.sqlmap_runner import SqlmapRunner

REAL_CONNECTION_FAILURE_OUTPUT = """
[20:00:11] [INFO] testing connection to the target URL
[20:00:11] [CRITICAL] unable to connect to the target URL ('Connection refused') or proxy. sqlmap is going to retry the request(s)
[20:00:11] [ERROR] unable to connect to the target URL ('Connection refused') or proxy, skipping to the next target
"""

REAL_CLEAN_SCAN_OUTPUT = """
[18:40:33] [WARNING] POST parameter 'query' does not seem to be injectable
[18:40:33] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options
"""


def test_detects_connection_failure():
    reason = SqlmapRunner._detect_failure_reason(REAL_CONNECTION_FAILURE_OUTPUT)
    assert reason == "unable to connect to the target url"


def test_legitimate_clean_scan_is_not_flagged_as_failure():
    reason = SqlmapRunner._detect_failure_reason(REAL_CLEAN_SCAN_OUTPUT)
    assert reason is None


def test_empty_output_is_not_flagged_as_failure():
    assert SqlmapRunner._detect_failure_reason("") is None


def test_heuristic_dbms_guess_does_not_trigger_premature_dbms_status():
    # Regresión: "it looks like the back-end DBMS is 'X'..." es una
    # SUPOSICIÓN heurística temprana (antes de confirmar cualquier
    # inyección), no la confirmación real. Mostrar "DBMS identificado"
    # ahí hace que el spinner muestre un estado engañosamente
    # avanzado mientras sqlmap recién está empezando a probar payloads.
    runner = SqlmapRunner()
    line = (
        "it looks like the back-end DBMS is 'MySQL'. Do you want to "
        "skip test payloads specific for other DBMSes? [Y/n] Y"
    )
    assert runner._parse_progress(line) == ""


def test_confirmed_dbms_line_still_triggers_status():
    runner = SqlmapRunner()
    line = "[19:45:26] [INFO] the back-end DBMS is MySQL"
    assert runner._parse_progress(line) == "DBMS identificado..."
