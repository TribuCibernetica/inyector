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


def test_confirmed_vulnerability_is_not_buried_by_later_stability_warning():
    # Regresión real (ITESCAM): sqlmap confirmó una inyección real
    # (time-based blind, severidad ALTO en el reporte -- imprimió
    # "sqlmap identified the following injection point(s)"), pero más
    # adelante en el MISMO log -- probando otro parámetro/técnica --
    # apareció "target url content is not stable". Sin este fix, eso
    # tapaba el hallazgo real y el resumen final decía "DESCONOCIDO".
    reason = SqlmapRunner._detect_failure_reason(
        "[18:40:33] [WARNING] target url content is not stable"
    )
    assert reason is not None  # el marcador sí se detecta en crudo...

    reconciled = SqlmapRunner._reconcile_failure_reason(reason, vuln_found=True)
    assert reconciled is None  # ...pero se descarta si ya hubo confirmación


def test_failure_reason_still_applies_without_a_confirmed_vulnerability():
    reason = SqlmapRunner._detect_failure_reason(
        "[18:40:33] [CRITICAL] unable to connect to the target URL"
    )
    reconciled = SqlmapRunner._reconcile_failure_reason(reason, vuln_found=False)
    assert reconciled == reason


def test_detects_shallow_scan_from_integer_casting_skip():
    # Regresión real (UT Tehuacán): con level 2/risk 1 (default),
    # sqlmap detectaba 'possible integer casting detected' en el
    # parámetro 'id' y lo saltaba automáticamente (--batch), concluyendo
    # 'no vulnerable' en segundos sin haber probado ninguna técnica SQLi
    # real. Con --level 5 --risk 3 el mismo target sí corrió una
    # batería completa. Este marcador avisa que vale la pena reintentar
    # con nivel/risk más alto antes de aceptar el 'NO'.
    reason = SqlmapRunner._detect_shallow_scan_reason(
        "[17:12:59] [ERROR] possible integer casting detected (e.g. "
        "'$id=intval($_REQUEST[\"id\"])') at the back-end web application"
    )
    assert reason == "possible integer casting detected"


def test_normal_clean_scan_has_no_shallow_scan_reason():
    reason = SqlmapRunner._detect_shallow_scan_reason(
        "[18:40:33] [WARNING] POST parameter 'query' does not seem to "
        "be injectable\n"
        "[18:40:33] [ERROR] all tested parameters do not appear to be "
        "injectable"
    )
    assert reason is None
