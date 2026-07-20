"""Tests para KnowledgeBase — la memoria de técnicas confirmadas.

El punto central a probar: una técnica confirmada se guarda y se
puede recuperar por fingerprint (sin necesidad de llamar a Gemini de
nuevo), y confirmar la MISMA técnica otra vez refuerza el contador en
vez de duplicarla.
"""

import json
import os

from inyector.intelligence.knowledge_base import KnowledgeBase


def test_fingerprint_is_stable_and_case_insensitive():
    stack = {"framework": "Django", "language": "Python"}
    orm = {"orm": "django_orm"}
    waf = {"waf": "Cloudflare"}
    dbms = {"name": "PostgreSQL"}

    fp1 = KnowledgeBase.fingerprint(stack, orm, waf, dbms)
    fp2 = KnowledgeBase.fingerprint(stack, orm, waf, dbms)
    assert fp1 == fp2
    assert fp1 == fp1.lower()


def test_fingerprint_does_not_include_url():
    # A propósito: el objetivo es reusar aprendizaje entre distintos
    # targets que comparten stack, no solo el mismo sitio de nuevo.
    stack = {"framework": "Django", "language": "Python"}
    orm = {"orm": "none"}
    waf = {"waf": "none"}
    fp = KnowledgeBase.fingerprint(stack, orm, waf)
    assert "http" not in fp
    assert "." not in fp or "com" not in fp


def test_record_and_retrieve_technique(tmp_path):
    kb = KnowledgeBase(str(tmp_path))
    fp = "django|python|django_orm|none|postgresql"

    kb.record_success(fp, "1' OR '1'='1", "B", "id", "boolean bypass clásico")

    known = kb.get_known_techniques(fp)
    assert len(known) == 1
    assert known[0]["payload"] == "1' OR '1'='1"
    assert known[0]["confirmations"] == 1


def test_recording_same_technique_twice_increments_confirmations(tmp_path):
    kb = KnowledgeBase(str(tmp_path))
    fp = "express|node|sequelize|none|mysql"

    kb.record_success(fp, "' OR SLEEP(5)-- -", "T", "id")
    kb.record_success(fp, "' OR SLEEP(5)-- -", "T", "id")
    kb.record_success(fp, "' OR SLEEP(5)-- -", "T", "id")

    known = kb.get_known_techniques(fp)
    assert len(known) == 1  # no se duplica
    assert known[0]["confirmations"] == 3


def test_different_fingerprints_do_not_mix_techniques(tmp_path):
    kb = KnowledgeBase(str(tmp_path))
    kb.record_success("django|python|django_orm|none|postgresql", "payload_a", "B", "id")
    kb.record_success("express|node|sequelize|none|mysql", "payload_b", "T", "id")

    assert len(kb.get_known_techniques("django|python|django_orm|none|postgresql")) == 1
    assert len(kb.get_known_techniques("express|node|sequelize|none|mysql")) == 1
    assert kb.get_known_techniques("stack_nunca_visto|x|x|x|x") == []


def test_persists_across_instances(tmp_path):
    fp = "laravel|php|eloquent|none|mysql"
    kb1 = KnowledgeBase(str(tmp_path))
    kb1.record_success(fp, "payload_persistente", "E", "id")

    kb2 = KnowledgeBase(str(tmp_path))  # nueva instancia, mismo output_dir
    known = kb2.get_known_techniques(fp)
    assert len(known) == 1
    assert known[0]["payload"] == "payload_persistente"


def test_corrupt_knowledge_file_is_ignored_not_crashed(tmp_path):
    knowledge_dir = tmp_path / ".inyector_knowledge"
    knowledge_dir.mkdir()
    (knowledge_dir / "techniques.json").write_text("{esto no es json valido")

    kb = KnowledgeBase(str(tmp_path))  # no debe lanzar excepción
    assert kb.get_known_techniques("cualquier|cosa") == []


def test_stats_reports_totals(tmp_path):
    kb = KnowledgeBase(str(tmp_path))
    kb.record_success("fp1", "payload1", "B", "id")
    kb.record_success("fp1", "payload2", "E", "id")
    kb.record_success("fp2", "payload3", "T", "id")

    stats = kb.stats()
    assert stats["fingerprints"] == 2
    assert stats["techniques"] == 3
