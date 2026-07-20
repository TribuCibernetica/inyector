"""Tests para ConfidenceCalibrator — cruce de evidencia Stack/ORM."""

from inyector.intelligence.confidence_calibrator import ConfidenceCalibrator


def test_consistent_stack_and_orm_boost_confidence():
    recon = {
        "stack": {"language": "python", "framework": "Django", "confidence": 0.5},
        "orm": {"orm": "django_orm", "confidence": 0.7},
    }
    ConfidenceCalibrator().calibrate(recon)

    assert recon["stack"]["confidence"] > 0.5
    assert recon["orm"]["confidence"] > 0.7
    assert recon["consistency_notes"]


def test_contradictory_stack_and_orm_lowers_confidence():
    # PHP no puede usar django_orm (es una librería exclusiva de Python)
    recon = {
        "stack": {"language": "php", "framework": "PHP nativo", "confidence": 0.5},
        "orm": {"orm": "django_orm", "confidence": 0.7},
    }
    ConfidenceCalibrator().calibrate(recon)

    assert recon["orm"]["confidence"] < 0.7
    assert any("Contradicción" in n for n in recon["consistency_notes"])


def test_unknown_stack_does_not_penalize_orm():
    recon = {
        "stack": {"language": "desconocido", "framework": "desconocido", "confidence": 0.0},
        "orm": {"orm": "sqlalchemy", "confidence": 0.7},
    }
    ConfidenceCalibrator().calibrate(recon)

    # Sin señal de lenguaje, no hay base para juzgar — no se penaliza.
    assert recon["orm"]["confidence"] == 0.7
    assert recon["consistency_notes"] == []


def test_no_orm_detected_produces_no_notes():
    recon = {
        "stack": {"language": "python", "framework": "Django", "confidence": 0.5},
        "orm": {"orm": "none", "confidence": 0.0},
    }
    ConfidenceCalibrator().calibrate(recon)
    assert recon["consistency_notes"] == []
