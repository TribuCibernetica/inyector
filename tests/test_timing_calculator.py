"""Tests para TimingCalculator.

Cubre measure_baseline (trimmed mean con >=3 muestras, promedio simple
con <3, y el default de 500ms cuando todas las muestras fallan) y
calculate_delay en modo stealth y no-stealth. Incluye un caso límite no
obvio: a diferencia de TechniqueSelector (que hace fallback a una
entrada "unknown" explícita), calculate_delay cae a
WAF_RATE_LIMITS["none"] -- todo en cero -- cuando el WAF no está en el
mapa, dejando el rate-limiting efectivamente desactivado para un WAF
no reconocido.
"""

from unittest.mock import MagicMock, patch

import pytest

from inyector.intelligence.timing_calculator import TimingCalculator


# ---------------------------------------------------------------------
# measure_baseline
# ---------------------------------------------------------------------

def test_measure_baseline_uses_trimmed_mean_with_three_or_more_samples():
    calculator = TimingCalculator()
    session = MagicMock()

    # 5 muestras -> elapsed en ms: 100, 200, 300, 50, 1000.
    # sorted: [50, 100, 200, 300, 1000] -> trimmed (sin min/max): [100, 200, 300]
    # mean = 200.0
    time_values = [
        0.0, 0.1,    # sample 1: 100ms
        0.2, 0.4,    # sample 2: 200ms
        0.5, 0.8,    # sample 3: 300ms
        0.9, 0.95,   # sample 4: 50ms
        1.0, 2.0,    # sample 5: 1000ms
    ]
    with patch("inyector.intelligence.timing_calculator.time.time", side_effect=time_values):
        baseline = calculator.measure_baseline("http://x.com", session, samples=5)

    assert baseline == pytest.approx(200.0)


def test_measure_baseline_uses_plain_mean_with_fewer_than_three_samples():
    calculator = TimingCalculator()
    session = MagicMock()
    # Falla en la 2da muestra -> solo 1 muestra exitosa (100ms).
    session.get.side_effect = [MagicMock(), Exception("boom")]

    time_values = [0.0, 0.1, 5.0]  # start/end sample1, start (sin end) sample2
    with patch("inyector.intelligence.timing_calculator.time.time", side_effect=time_values):
        baseline = calculator.measure_baseline("http://x.com", session, samples=2)

    assert baseline == pytest.approx(100.0)


def test_measure_baseline_returns_default_when_all_samples_fail():
    calculator = TimingCalculator()
    session = MagicMock()
    session.get.side_effect = Exception("connection refused")

    baseline = calculator.measure_baseline("http://x.com", session, samples=3)

    assert baseline == 500.0


# ---------------------------------------------------------------------
# calculate_delay - stealth mode
# ---------------------------------------------------------------------

def test_calculate_delay_stealth_with_no_waf_allows_delay_of_one():
    calculator = TimingCalculator(stealth_mode=True)
    result = calculator.calculate_delay(baseline_ms=100, waf="none")

    # delay = max(1, int(150/1000)) = 1, y no se fuerza el piso de 2
    # porque waf == "none".
    assert result["delay"] == 1
    assert result["timeout"] == 30
    assert result["retries"] == 5
    assert result["safe_freq"] == 0  # requests_before_pause de "none" es 0


def test_calculate_delay_stealth_with_known_waf_enforces_minimum_delay_of_two():
    calculator = TimingCalculator(stealth_mode=True)
    result = calculator.calculate_delay(baseline_ms=100, waf="cloudflare")

    # delay crudo sería max(1, int(150/1000)) = 1, pero como waf != "none"
    # se fuerza un piso de 2.
    assert result["delay"] == 2
    assert result["timeout"] == 30
    assert result["retries"] == 5
    assert result["safe_freq"] == 10  # 20 // 2


def test_calculate_delay_stealth_scales_with_high_baseline():
    calculator = TimingCalculator(stealth_mode=True)
    result = calculator.calculate_delay(baseline_ms=5000, waf="aws_waf")

    assert result["delay"] == 7        # int(5000*1.5/1000) = 7
    assert result["timeout"] == 50     # int(5000*10/1000) = 50
    assert result["retries"] == 5
    assert result["safe_freq"] == 15   # 30 // 2


def test_calculate_delay_stealth_with_unmapped_waf_disables_rate_limiting():
    # Caso límite: un WAF no presente en WAF_RATE_LIMITS cae al perfil
    # "none" (todo en cero) en vez de a un "unknown" conservador.
    calculator = TimingCalculator(stealth_mode=True)
    result = calculator.calculate_delay(baseline_ms=100, waf="un_waf_inexistente")

    assert result["safe_freq"] == 0
    # El delay sigue con el piso de 2 porque waf != "none" (aunque no
    # esté mapeado), a pesar de que el rate-limiting quedó en cero.
    assert result["delay"] == 2


# ---------------------------------------------------------------------
# calculate_delay - non-stealth mode
# ---------------------------------------------------------------------

def test_calculate_delay_non_stealth_ignores_baseline_and_waf():
    calculator = TimingCalculator(stealth_mode=False)

    result_a = calculator.calculate_delay(baseline_ms=100, waf="none")
    result_b = calculator.calculate_delay(baseline_ms=99999, waf="cloudflare")

    expected = {"delay": 0, "timeout": 30, "retries": 3, "safe_freq": 0}
    assert result_a == expected
    assert result_b == expected
