"""Tests para WAFBypassProber.

El escenario central: itescam.edu.mx, el mismo target grounded en
project_inyector_itescam_finding.md -- dos reglas de WAF confirmadas a
mano ('AND'/'OR' + espacio literal bloqueado con sinkhole-redirect a un
dominio ajeno, bypasseable con '/**/'; keyword 'SELECT' desnuda
bloqueada sin importar el delimitador, bypasseable removiéndola vía
scalarfuncbypass). El prober debe redescubrir ambas reglas solo, con
requests HTTP crudos (mockeados acá, sin red real), en el mismo orden
exacto en que discover() los dispara.
"""

from unittest.mock import MagicMock

from inyector.recon.waf_bypass_prober import WAFBypassProber


def _response(status_code=200, headers=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    return resp


def _clean():
    return _response(200, text="pagina normal de contenido")


def _sinkhole_block():
    return _response(
        302, headers={"Location": "https://noexiste.com.mx/"},
    )


def _bypassed_like_clean():
    # Misma forma que _clean() -- responses_similar compara status +
    # longitud de body.
    return _response(200, text="pagina normal de contenido")


def test_itescam_scenario_discovers_both_known_bypasses():
    session = MagicMock()
    session.get.side_effect = [
        _clean(),               # control limpio
        _sinkhole_block(),      # baseline 'AND 1=1' -- bloqueado
        _bypassed_like_clean(), # 'AND/**/1=1' -- bypass confirmado, corta el loop
        _sinkhole_block(),      # SELECT envuelto -- bloqueado
        _bypassed_like_clean(), # SELECT removido -- bypass confirmado
    ]

    result = WAFBypassProber().discover(
        "https://www.itescam.edu.mx/portal/noticias.php", session, "id",
    )

    assert result["baseline_blocked"] is True
    assert "space2comment" in result["confirmed_tampers"]
    assert "scalarfuncbypass" in result["confirmed_tampers"]
    assert session.get.call_count == 5


def test_no_baseline_block_short_circuits_with_no_tampers():
    session = MagicMock()
    session.get.side_effect = [_clean(), _clean()]

    result = WAFBypassProber().discover(
        "http://example.com/page.php", session, "id",
    )

    assert result["baseline_blocked"] is False
    assert result["confirmed_tampers"] == []
    assert session.get.call_count == 2


def test_reports_honestly_when_nothing_bypasses():
    # Baseline bloqueado, pero NINGUNA mutación (ni las 3 de espacio, ni
    # case-randomization, ni la de SELECT) lo esquiva -- debe reportar
    # explícitamente qué se probó, sin confirmar tampers que no
    # funcionaron.
    session = MagicMock()
    session.get.side_effect = [
        _clean(),
        _sinkhole_block(),   # baseline
        _sinkhole_block(),   # /**/
        _sinkhole_block(),   # +
        _sinkhole_block(),   # espacio doble
        _sinkhole_block(),   # case-randomization
        _sinkhole_block(),   # SELECT envuelto
        _sinkhole_block(),   # SELECT removido -- también bloqueado
    ]

    result = WAFBypassProber().discover(
        "https://www.itescam.edu.mx/portal/noticias.php", session, "id",
    )

    assert result["baseline_blocked"] is True
    assert result["confirmed_tampers"] == []
    assert len(result["tested"]) >= 5


def test_network_failure_is_treated_as_blocked_not_bypassed():
    # Un timeout/conexión rechazada es indistinguible de un bloqueo
    # agresivo -- no debe confundirse con "el bypass funcionó". Tras la
    # request 2 (baseline), toda request real fallaría con
    # ConnectionError -- session.get lo lanza, _safe_get lo atrapa y
    # devuelve None.
    import requests as requests_module

    session = MagicMock()
    responses = iter([_clean(), _sinkhole_block()])

    def _get(*args, **kwargs):
        try:
            return next(responses)
        except StopIteration:
            raise requests_module.exceptions.ConnectionError("boom")

    session.get.side_effect = _get

    result = WAFBypassProber().discover(
        "https://www.itescam.edu.mx/portal/noticias.php", session, "id",
    )

    # Ninguna mutación debe quedar confirmada solo porque las requests
    # de prueba fallaron de red.
    assert result["confirmed_tampers"] == []
