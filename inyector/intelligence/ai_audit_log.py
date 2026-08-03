"""Bitácora persistente de toda interacción con el asistente de IA.

A diferencia de KnowledgeBase (que solo guarda técnicas confirmadas),
esto registra CADA llamada a Gemini -- prompt completo, respuesta
cruda, y CADA sugerencia recibida, confirmada o no -- para que las
decisiones de la IA queden auditables después del scan. Sin esto, una
sugerencia que Gemini descartó como "no confirmada" desaparecía sin
dejar rastro de qué la motivó.

Un archivo JSONL (un objeto JSON por línea) en vez de un único JSON
para poder ir agregando entradas de forma segura entre corridas sin
tener que releer/reescribir todo el archivo.
"""

import json
import os
from datetime import datetime

from inyector.utils.logger import get_logger

logger = get_logger(__name__)

AUDIT_SUBDIR = ".inyector_knowledge"
AUDIT_FILE = "ai_decisions.jsonl"


class AIAuditLog:
    """Escribe un registro por línea de cada decisión/interacción de IA."""

    def __init__(self, output_dir: str):
        log_dir = os.path.join(output_dir, AUDIT_SUBDIR)
        os.makedirs(log_dir, exist_ok=True)
        self.path = os.path.join(log_dir, AUDIT_FILE)

    def record(self, **fields) -> None:
        """Agrega una entrada a la bitácora.

        Args:
            **fields: campos arbitrarios de la entrada (kind, model,
                prompt, raw_response, suggestions, error, etc.). Se le
                agrega automáticamente un timestamp.
        """
        entry = {"timestamp": datetime.now().isoformat(), **fields}
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            logger.warning(f"No se pudo escribir en la bitácora de IA: {e}")
