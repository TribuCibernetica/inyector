"""Memoria persistente de técnicas de inyección confirmadas.

Le da a la fase de IA una economía de tokens real: en vez de
preguntarle a Gemini desde cero en cada scan, primero se prueban las
técnicas que YA se confirmaron como exitosas contra un fingerprint de
stack similar (gratis, sin llamada a la API, sin latencia). Solo se
le pregunta a Gemini algo nuevo cuando no hay nada conocido para ese
fingerprint, o lo conocido no funcionó contra este target puntual.

El fingerprint NO incluye la URL/dominio a propósito — el objetivo es
reusar aprendizaje entre DISTINTOS targets que comparten stack/ORM/WAF
(ej. "todos los sitios Django+PostgreSQL detrás de Cloudflare que vimos
alguna vez"), no solo volver a escanear el mismo sitio.
"""

import json
import os
from typing import Optional

from inyector.utils.logger import get_logger

logger = get_logger(__name__)

KNOWLEDGE_SUBDIR = ".inyector_knowledge"
KNOWLEDGE_FILE = "techniques.json"


class KnowledgeBase:
    """Guarda y recupera técnicas de inyección confirmadas, por fingerprint."""

    def __init__(self, output_dir: str):
        knowledge_dir = os.path.join(output_dir, KNOWLEDGE_SUBDIR)
        os.makedirs(knowledge_dir, exist_ok=True)
        self.path = os.path.join(knowledge_dir, KNOWLEDGE_FILE)
        self._data = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Knowledge base corrupta, se ignora: {e}")
            return {}

    def _save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.warning(f"No se pudo guardar la knowledge base: {e}")

    @staticmethod
    def fingerprint(stack: dict, orm: dict, waf: dict,
                     dbms: Optional[dict] = None) -> str:
        """Genera una clave estable a partir del fingerprint del target.

        Args:
            stack: resultado de StackDetector.
            orm: resultado de ORMDetector.
            waf: resultado de WAFDetector.
            dbms: info de DBMS si ya se conoce (opcional).

        Returns:
            Clave string estable, ej. "django|python|django_orm|cloudflare|postgresql".
        """
        parts = [
            stack.get("framework", "unknown"),
            stack.get("language", "unknown"),
            orm.get("orm", "none"),
            waf.get("waf", "none"),
            (dbms or {}).get("name", "unknown"),
        ]
        return "|".join(str(p).lower() for p in parts)

    def get_known_techniques(self, fingerprint_key: str) -> list[dict]:
        """Devuelve técnicas conocidas para este fingerprint, ordenadas
        por cuántas veces se confirmaron (las más probadas primero)."""
        entry = self._data.get(fingerprint_key, {})
        techniques = entry.get("techniques", [])
        return sorted(
            techniques, key=lambda t: t.get("confirmations", 1), reverse=True,
        )

    def record_success(self, fingerprint_key: str, payload: str,
                        technique: str, injection_point: str = "param",
                        reasoning: str = "") -> None:
        """Registra (o refuerza, si ya existía) una técnica confirmada."""
        entry = self._data.setdefault(fingerprint_key, {"techniques": []})

        for t in entry["techniques"]:
            if t["payload"] == payload and t["injection_point"] == injection_point:
                t["confirmations"] = t.get("confirmations", 1) + 1
                self._save()
                return

        entry["techniques"].append({
            "payload": payload,
            "technique": technique,
            "injection_point": injection_point,
            "reasoning": reasoning,
            "confirmations": 1,
        })
        self._save()
        logger.info(
            f"Técnica aprendida y guardada para fingerprint '{fingerprint_key}'"
        )

    def record_csrf_field(self, fingerprint_key: str, field: str,
                           url_pattern: str) -> None:
        """Registra el campo CSRF/token dinámico usado con éxito (scan
        real, no necesariamente SQLi confirmada) contra este
        fingerprint -- señal INFORMATIVA para scans futuros contra
        OTRO target del mismo stack (ver get_known_csrf_field). No
        autoritativa: la detección en vivo del form real crawleado
        siempre gana si difiere -- dos targets del mismo stack pueden
        nombrar su campo distinto.
        """
        entry = self._data.setdefault(fingerprint_key, {"techniques": []})
        known = entry.setdefault("csrf_fields", [])

        for c in known:
            if c["field"] == field:
                c["confirmations"] = c.get("confirmations", 1) + 1
                self._save()
                return

        known.append({
            "field": field,
            "url_pattern": url_pattern,
            "confirmations": 1,
        })
        self._save()

    def get_known_csrf_field(self, fingerprint_key: str) -> Optional[str]:
        """Campo CSRF más confirmado para este fingerprint, si hay
        alguno -- solo para mostrar como sugerencia en consola/reporte,
        NUNCA se auto-aplica a scan_config."""
        known = self._data.get(fingerprint_key, {}).get("csrf_fields", [])
        if not known:
            return None
        return max(known, key=lambda c: c.get("confirmations", 1))["field"]

    def stats(self) -> dict:
        """Resumen de cuánto aprendió la knowledge base hasta ahora."""
        total_techniques = sum(
            len(v.get("techniques", [])) for v in self._data.values()
        )
        return {
            "fingerprints": len(self._data),
            "techniques": total_techniques,
        }
