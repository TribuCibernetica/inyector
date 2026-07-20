"""Tests para TamperSelector — en particular el fallback para WAFs
detectados que no están explícitamente en el mapa (antes se quedaban
sin ningún tamper, lo cual es peor que un set genérico razonable)."""

from inyector.intelligence.tamper_selector import TamperSelector


def test_known_waf_returns_specific_tampers():
    selector = TamperSelector()
    tampers = selector.select(waf="aws_waf")
    assert "greatest" in tampers
    assert tampers == TamperSelector.WAF_TAMPER_MAP["aws_waf"]


def test_no_waf_returns_no_tampers():
    selector = TamperSelector()
    assert selector.select(waf="none") == []
    assert selector.select(waf=None) == []


def test_unmapped_waf_falls_back_to_generic_unknown_set():
    selector = TamperSelector()
    tampers = selector.select(waf="un_waf_que_no_existe_en_el_mapa")
    assert tampers == TamperSelector.WAF_TAMPER_MAP["unknown"]
    assert tampers != []


def test_orm_extra_tampers_are_appended_without_duplicates():
    selector = TamperSelector()
    tampers = selector.select(waf="none", orm="django_orm")
    assert "space2comment" in tampers
    assert len(tampers) == len(set(tampers))
