"""Tests para TechniqueSelector.

Cubre los distintos caminos de selección (forzado por usuario, stealth
con/sin WAF, modo rápido con/sin WAF) y un caso no obvio: en modo
stealth con waf="none", el selector devuelve "BEUSTQ" (el perfil
"aggressive" completo) en lugar de un subset conservador -- porque
WAF_TECHNIQUE_MAP["none"] = "BEUSTQ", y el modo stealth solo modera
técnicas cuando SÍ hay un WAF detectado.
"""

from inyector.intelligence.technique_selector import TechniqueSelector


def test_user_technique_forces_result_and_is_uppercased():
    selector = TechniqueSelector()
    assert selector.select(waf="cloudflare", stealth=True, user_technique="but") == "BUT"


def test_empty_user_technique_does_not_short_circuit():
    # "" es falsy en Python -> debe caer al flujo normal, no devolver "".
    selector = TechniqueSelector()
    result = selector.select(waf="none", stealth=True, user_technique="")
    assert result != ""
    assert result == TechniqueSelector.WAF_TECHNIQUE_MAP["none"]


def test_stealth_with_known_waf_uses_waf_technique_map():
    selector = TechniqueSelector()
    assert selector.select(waf="aws_waf", stealth=True) == "BET"
    assert selector.select(waf="wordfence", stealth=True) == "BET"


def test_stealth_with_unknown_waf_falls_back_to_bt():
    selector = TechniqueSelector()
    result = selector.select(waf="un_waf_inexistente", stealth=True)
    assert result == "BT"


def test_stealth_with_no_waf_returns_full_aggressive_set():
    # Comportamiento no obvio: stealth=True + waf="none" NO es
    # conservador -- devuelve el set completo BEUSTQ porque así está
    # definido en WAF_TECHNIQUE_MAP["none"].
    selector = TechniqueSelector()
    result = selector.select(waf="none", stealth=True)
    assert result == "BEUSTQ"
    assert result == TechniqueSelector.TECHNIQUE_PROFILES["aggressive"]


def test_non_stealth_with_no_waf_uses_aggressive_profile():
    selector = TechniqueSelector()
    result = selector.select(waf="none", stealth=False)
    assert result == TechniqueSelector.TECHNIQUE_PROFILES["aggressive"]
    assert result == "BEUSTQ"


def test_non_stealth_with_known_waf_uses_waf_technique_map():
    selector = TechniqueSelector()
    assert selector.select(waf="barracuda", stealth=False) == "BEUT"


def test_non_stealth_with_unknown_waf_falls_back_to_beut():
    selector = TechniqueSelector()
    result = selector.select(waf="un_waf_inexistente", stealth=False)
    assert result == "BEUT"
    assert result == TechniqueSelector.TECHNIQUE_PROFILES["normal"]


def test_user_technique_wins_even_over_none_waf_and_non_stealth():
    selector = TechniqueSelector()
    result = selector.select(waf="none", stealth=False, user_technique="q")
    assert result == "Q"
