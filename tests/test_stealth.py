"""Tests para StealthEngine — sobre todo el clamping de human_delay
(un gauss extremo no debe producir un delay negativo ni fuera del
rango pedido) y las pausas automáticas por WAF basadas en intervalos
de requests.
"""

from inyector.utils.stealth import StealthEngine


def test_human_delay_stays_within_configured_range(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda seconds: sleeps.append(seconds))

    engine = StealthEngine()
    for _ in range(50):
        engine.human_delay(min_ms=100, max_ms=500)

    assert len(sleeps) == 50
    assert all(0.1 <= s <= 0.5 for s in sleeps)


def test_human_delay_clamps_extreme_low_gauss_to_min(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda seconds: sleeps.append(seconds))
    monkeypatch.setattr("random.gauss", lambda mean, std: -10_000)

    engine = StealthEngine()
    engine.human_delay(min_ms=800, max_ms=3000)

    assert sleeps == [0.8]


def test_human_delay_clamps_extreme_high_gauss_to_max(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda seconds: sleeps.append(seconds))
    monkeypatch.setattr("random.gauss", lambda mean, std: 10_000)

    engine = StealthEngine()
    engine.human_delay(min_ms=800, max_ms=3000)

    assert sleeps == [3.0]


def test_detect_throttling_needs_at_least_three_samples():
    engine = StealthEngine()
    assert engine.detect_throttling([]) is False
    assert engine.detect_throttling([100, 200]) is False


def test_detect_throttling_true_when_progressively_slower():
    engine = StealthEngine()
    # Cada tiempo es más de 1.5x el anterior.
    assert engine.detect_throttling([100, 200, 400]) is True


def test_detect_throttling_false_when_stable():
    engine = StealthEngine()
    assert engine.detect_throttling([100, 110, 105]) is False


def test_should_pause_none_waf_never_pauses():
    engine = StealthEngine()
    assert engine.should_pause(20, "none") == (False, 0.0)
    assert engine.should_pause(1000, "none") == (False, 0.0)


def test_should_pause_triggers_exactly_at_interval_multiple():
    engine = StealthEngine()
    # cloudflare: interval=20, min_pause=10, max_pause=30
    should_pause, duration = engine.should_pause(20, "cloudflare")
    assert should_pause is True
    assert 10 <= duration <= 30

    should_pause, duration = engine.should_pause(19, "cloudflare")
    assert (should_pause, duration) == (False, 0.0)


def test_should_pause_request_count_zero_never_pauses():
    engine = StealthEngine()
    # 0 % cualquier intervalo == 0, pero no hay requests aún.
    assert engine.should_pause(0, "cloudflare") == (False, 0.0)


def test_should_pause_literal_unknown_waf_uses_unknown_config():
    engine = StealthEngine()
    should_pause, duration = engine.should_pause(20, "unknown")
    assert should_pause is True
    assert 10 <= duration <= 20  # rango de "unknown"


def test_should_pause_arbitrary_unmapped_waf_defaults_to_none_config():
    # A diferencia de TamperSelector, el .get() de should_pause usa
    # WAF_PAUSE_CONFIG["none"] como default — no ["unknown"] — así que
    # un string de WAF que no está en el mapa (y que no sea la clave
    # literal "unknown") nunca dispara una pausa.
    engine = StealthEngine()
    assert engine.should_pause(20, "un_waf_inexistente") == (False, 0.0)


def test_adaptive_delay_doubles_base_when_throttling_detected(monkeypatch):
    captured = {}

    def fake_human_delay(self, min_ms, max_ms):
        captured["min_ms"] = min_ms
        captured["max_ms"] = max_ms

    monkeypatch.setattr(StealthEngine, "human_delay", fake_human_delay)

    engine = StealthEngine()
    engine.adaptive_delay([100, 200, 400], base_delay_ms=800)

    assert captured["min_ms"] == 1600
    assert captured["max_ms"] == 3200


def test_adaptive_delay_uses_base_when_no_throttling(monkeypatch):
    captured = {}

    def fake_human_delay(self, min_ms, max_ms):
        captured["min_ms"] = min_ms
        captured["max_ms"] = max_ms

    monkeypatch.setattr(StealthEngine, "human_delay", fake_human_delay)

    engine = StealthEngine()
    engine.adaptive_delay([100, 110, 105], base_delay_ms=800)

    assert captured["min_ms"] == 800
    assert captured["max_ms"] == 1600
