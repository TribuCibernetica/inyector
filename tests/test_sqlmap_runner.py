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


def test_recovered_instability_warning_with_real_testing_is_not_a_failure():
    # Regresión real (cloud.teziutlan.tecnm.mx, login WebForms): el
    # VIEWSTATE/EVENTVALIDATION se regeneran en cada respuesta, así que
    # sqlmap SIEMPRE imprime 'target url content is not stable' contra
    # este target -- pero lo recupera solo (marca contenido dinámico,
    # cambia a comparación por texto) y sigue probando de verdad.
    # Confirmado corriendo sqlmap directo (sin el wrapper) contra el
    # mismo request exacto que un scan de inyector había marcado
    # 'DESCONOCIDO': un scan real de 9+ minutos terminó en
    # 'does not seem to be injectable', no en una falla de conexión.
    # Antes de este fix, la sola presencia de la frase de inestabilidad
    # tapaba ese resultado real y correcto.
    stdout = """
[19:37:48] [WARNING] target URL content is not stable (i.e. content differs). sqlmap will base the page comparison on a sequence matcher.
[19:37:49] [INFO] dynamic content marked for removal (12 regions)
[19:37:56] [WARNING] target URL content appears to be too dynamic. Switching to '--text-only'
[19:37:57] [INFO] testing for SQL injection on POST parameter 'ctl00$cphContenido$txtNoControl'
[19:37:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[19:38:38] [WARNING] POST parameter 'ctl00$cphContenido$txtNoControl' does not seem to be injectable
[19:38:38] [ERROR] all tested parameters do not appear to be injectable
"""
    assert SqlmapRunner._detect_failure_reason(stdout) is None


def test_instability_warning_without_real_testing_is_still_a_failure():
    # El otro lado de la regresión de arriba: si la advertencia de
    # inestabilidad aparece pero sqlmap NUNCA llega a probar el
    # parámetro real (sin la línea 'testing for sql injection on'),
    # sigue siendo un fallo real -- no hay que confiar en el 'NO'.
    stdout = """
[19:37:48] [WARNING] target URL content is not stable (i.e. content differs).
[19:37:49] [CRITICAL] target URL content appears to be heavily dynamic, sqlmap is going to retry the request(s)
"""
    reason = SqlmapRunner._detect_failure_reason(stdout)
    assert reason == "target url content is not stable"


def test_normal_clean_scan_has_no_shallow_scan_reason():
    reason = SqlmapRunner._detect_shallow_scan_reason(
        "[18:40:33] [WARNING] POST parameter 'query' does not seem to "
        "be injectable\n"
        "[18:40:33] [ERROR] all tested parameters do not appear to be "
        "injectable"
    )
    assert reason is None
