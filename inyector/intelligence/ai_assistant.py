"""Asistente de IA (Gemini) para sugerencias de explotación avanzadas.

Estrictamente opt-in (--ai-assist + GEMINI_API_KEY) y usado en un
puñado de puntos de decisión puntuales — NO reemplaza el pipeline
determinista (WAF/tamper/técnica siguen siendo reglas explicables y
100% reproducibles). Se llama solo cuando:

  1. sqlmap termina en un resultado ambiguo/fallido (ej. "target url
     content is not stable") y hace falta criterio para decidir qué
     intentar distinto — no un simple retry a ciegas.
  2. Un scan normal (con sqlmap + payloads conocidos del
     KnowledgeBase) no encontró nada, y se le pide una segunda opinión
     con payloads más creativos/específicos del stack detectado —
     second-order, contextos poco comunes, particularidades del ORM.

Antes de llamar a la API SIEMPRE se consulta el KnowledgeBase (ver
knowledge_base.py) — si ya se aprendió que algo funciona contra un
fingerprint de stack similar, eso se prueba primero, sin gastar
tokens ni latencia de red.

Nota de confidencialidad: activar esto manda al target (URL,
fragmentos de respuesta, mensajes de error) a la API de Gemini de
Google. Es responsabilidad del usuario confirmar que esto es
aceptable para el alcance de su auditoría antes de usar --ai-assist.
"""

import os
import time
from typing import Optional

from pydantic import BaseModel, Field

from inyector.intelligence.ai_audit_log import AIAuditLog
from inyector.utils.logger import get_logger

logger = get_logger(__name__)

# El rol se define como "pentester experto autorizado", no "black hat"
# literal — el resultado práctico que importa (creatividad y
# agresividad de un atacante real para encontrar lo que las
# herramientas automatizadas por defecto no encuentran) es el mismo,
# pero enmarcado de forma consistente con el resto de la herramienta
# (DISCLAIMER.md, uso autorizado únicamente) en vez de instruir al
# modelo a asumir un rol malicioso/no autorizado.
SYSTEM_INSTRUCTION = """Sos un especialista senior en seguridad ofensiva \
(penetration tester) con años de experiencia encontrando SQL injection \
en aplicaciones reales, incluyendo casos que las herramientas \
automatizadas estándar (sqlmap con su configuración por defecto) no \
detectan: segundo orden, contextos JSON/XML embebidos, bypass de WAF \
con encodings poco comunes, particularidades de ORMs específicos, e \
inyección a través de headers/cookies no obvios.

Este análisis es parte de una auditoría de seguridad AUTORIZADA \
(pentest, bug bounty, o CTF) ejecutada con consentimiento explícito \
del dueño del sistema. Tu trabajo es pensar como lo haría un atacante \
real y experimentado — sin asumir que "si sqlmap no lo encontró, no \
está" — pero siempre dentro de ese alcance autorizado: nunca sugieras \
acciones destructivas (DROP, DELETE, UPDATE masivos) ni nada que \
vaya más allá de detectar y confirmar la vulnerabilidad.

Respondé siempre en el formato JSON estructurado solicitado, sin \
texto adicional fuera del schema."""


class PayloadSuggestion(BaseModel):
    payload: str = Field(description="El payload SQL exacto a probar")
    technique: str = Field(
        description="Técnica sqlmap más cercana (B/E/U/S/T/Q) o 'custom'"
    )
    injection_point: str = Field(
        description="Dónde probarlo: 'param', 'header:X-Forwarded-For', "
                    "'cookie:session', 'second-order', etc."
    )
    reasoning: str = Field(
        description="Por qué este payload podría funcionar específicamente "
                    "contra este stack/ORM/WAF"
    )


class PayloadSuggestions(BaseModel):
    suggestions: list[PayloadSuggestion]


class SqlmapRecovery(BaseModel):
    suggested_flags: list[str] = Field(
        description="Flags adicionales o distintos de sqlmap a probar"
    )
    reasoning: str


class AICallBudget:
    """Tope compartido de llamadas a Gemini para toda la corrida.

    Una sola instancia se comparte entre todos los targets de un
    --crawl-all (o un único scan) -- sin esto, un --crawl-all con
    muchos candidatos puede terminar llamando a la API decenas de
    veces sin que el usuario haya decidido eso explícitamente. Con
    max_calls=None el tope queda desactivado (comportamiento actual).
    """

    def __init__(self, max_calls: Optional[int] = None):
        self.max_calls = max_calls
        self.calls_made = 0

    @property
    def exhausted(self) -> bool:
        return self.max_calls is not None and self.calls_made >= self.max_calls

    def consume(self) -> None:
        self.calls_made += 1


class AIAssistant:
    """Wrapper del cliente de Gemini para sugerencias puntuales de SQLi."""

    # docker-compose.yml siempre define GEMINI_MODEL en el contenedor
    # (aunque sea "" cuando el usuario no lo configuró) -- os.environ.get
    # con default solo aplica cuando la variable está AUSENTE, no cuando
    # está presente pero vacía, así que el "or" es necesario para no
    # terminar mandándole a la API un modelo "" (esto rompía con un 404
    # "Model '' not found").
    DEFAULT_MODEL = os.environ.get("GEMINI_MODEL") or "gemini-2.5-flash"

    def __init__(self, api_key: Optional[str] = None,
                 audit_log: Optional[AIAuditLog] = None,
                 budget: Optional[AICallBudget] = None):
        """Inicializa el cliente de Gemini.

        Args:
            api_key: API key de Gemini. Si se omite, se busca en la
                variable de entorno GEMINI_API_KEY.
            audit_log: si se pasa, cada llamada (prompt completo,
                respuesta cruda, latencia, error) queda registrada ahí
                para poder auditar después qué decidió Gemini y por
                qué — incluso las sugerencias que no se confirmaron.
            budget: tope compartido de llamadas a la API (--ai-max-calls).
                Si se omite, no hay límite.

        Raises:
            ValueError: si no hay API key disponible por ningún lado.
        """
        api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY no configurada — --ai-assist requiere una "
                "API key de Gemini (ver README: 'Asistente de IA (opcional)')"
            )

        self._audit_log = audit_log
        self._budget = budget

        from google import genai
        self._client = genai.Client(api_key=api_key)

    def _check_budget(self, kind: str) -> bool:
        """Devuelve True si todavía hay presupuesto para llamar a
        Gemini. Si ya se agotó, deja constancia en la bitácora para
        que quede tan auditable como cualquier otra decisión de IA."""
        if self._budget is None or not self._budget.exhausted:
            return True

        logger.info(
            f"Tope de llamadas a Gemini alcanzado (--ai-max-calls="
            f"{self._budget.max_calls}) — se omite '{kind}'"
        )
        if self._audit_log:
            self._audit_log.record(
                kind=kind, model=self.DEFAULT_MODEL,
                skipped_reason="ai_max_calls_exhausted",
                calls_made=self._budget.calls_made,
                max_calls=self._budget.max_calls,
            )
        return False

    def suggest_advanced_payloads(
        self, stack: dict, orm: dict, waf: dict,
        param_name: str, sample_response: str,
        already_tried: Optional[list[str]] = None,
    ) -> list[dict]:
        """Pide payloads avanzados/creativos específicos del stack detectado.

        Se usa cuando sqlmap (con la configuración estándar, más lo
        que ya sabíamos del KnowledgeBase) no encontró nada — el
        objetivo es cubrir el "long tail" de casos que solo un
        pentester experimentado probaría manualmente.

        Args:
            stack: resultado de StackDetector.
            orm: resultado de ORMDetector.
            waf: resultado de WAFDetector.
            param_name: parámetro bajo prueba.
            sample_response: fragmento de una respuesta real del
                target, para que el modelo tenga contexto concreto
                (no solo texto genérico).
            already_tried: payloads ya probados sin éxito, para que
                no sugiera lo mismo.

        Returns:
            Lista de dicts {payload, technique, injection_point, reasoning}.
            Lista vacía si la API falla — nunca lanza excepción hacia
            arriba (esto es una sugerencia best-effort, no algo de lo
            que dependa el resto del pipeline).
        """
        if not self._check_budget("suggest_advanced_payloads"):
            return []

        already_tried = already_tried or []

        prompt = f"""Contexto del target:
- Framework/Stack: {stack.get('framework', 'desconocido')} ({stack.get('language', 'desconocido')})
- ORM detectado: {orm.get('orm', 'ninguno')}
- Escape hatches conocidos del ORM: {orm.get('escape_hatches', [])}
- WAF detectado: {waf.get('waf', 'ninguno')}
- Parámetro bajo prueba: {param_name}
- Payloads ya probados sin éxito (no repitas estos): {already_tried[:20]}

Fragmento de una respuesta real del target (puede contener pistas del
motor de BD o del framework):
---
{sample_response[:2000]}
---

sqlmap con configuración estándar no encontró nada acá. Sugerime hasta
5 payloads de SQL injection AVANZADOS y ESPECÍFICOS para este stack/ORM
en particular que sqlmap típicamente no prueba por defecto — pensá en
second-order injection, bypass específico de este ORM, contextos poco
comunes (headers, JSON anidado), o encodings que evadan el WAF
detectado."""

        logger.debug(f"[Gemini] Prompt enviado (suggest_advanced_payloads):\n{prompt}")
        start = time.time()
        if self._budget is not None:
            self._budget.consume()
        try:
            from google.genai import types

            response = self._client.models.generate_content(
                model=self.DEFAULT_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    response_mime_type="application/json",
                    response_schema=PayloadSuggestions,
                ),
            )
            latency_ms = round((time.time() - start) * 1000, 1)
            result = response.parsed
            if not isinstance(result, PayloadSuggestions):
                raise ValueError(
                    f"Gemini no devolvió JSON validable contra el schema: "
                    f"{(response.text or '')[:500]!r}"
                )
            logger.info(
                f"Gemini sugirió {len(result.suggestions)} payload(s) avanzado(s)"
            )
            suggestions = [s.model_dump() for s in result.suggestions]
            if self._audit_log:
                self._audit_log.record(
                    kind="suggest_advanced_payloads",
                    model=self.DEFAULT_MODEL,
                    system_instruction=SYSTEM_INSTRUCTION,
                    prompt=prompt,
                    raw_response=response.text,
                    suggestions=suggestions,
                    latency_ms=latency_ms,
                    error=None,
                )
            return suggestions
        except Exception as e:
            logger.warning(f"Gemini no pudo sugerir payloads (se omite): {e}")
            if self._audit_log:
                self._audit_log.record(
                    kind="suggest_advanced_payloads",
                    model=self.DEFAULT_MODEL,
                    system_instruction=SYSTEM_INSTRUCTION,
                    prompt=prompt,
                    raw_response=None,
                    suggestions=[],
                    latency_ms=round((time.time() - start) * 1000, 1),
                    error=str(e),
                )
            return []

    def suggest_sqlmap_recovery(self, failure_reason: str,
                                 sqlmap_tail: str, scan_config: dict) -> dict:
        """Sugiere flags de sqlmap cuando termina en un resultado
        ambiguo/fallido (ej. 'target url content is not stable' por
        una respuesta con JWT/timestamp variable).

        Args:
            failure_reason: motivo detectado por SqlmapRunner.
            sqlmap_tail: últimas líneas del output real de sqlmap.
            scan_config: configuración usada en el scan.

        Returns:
            Dict {suggested_flags: list[str], reasoning: str}. Listas
            vacías si la API falla.
        """
        if not self._check_budget("suggest_sqlmap_recovery"):
            return {"suggested_flags": [], "reasoning": ""}

        prompt = f"""sqlmap terminó con este problema: '{failure_reason}'

Comando usado (resumen): técnica={scan_config.get('technique')}, \
level={scan_config.get('level')}, risk={scan_config.get('risk')}

Últimas líneas del output real de sqlmap:
---
{sqlmap_tail[-2000:]}
---

Dame flags adicionales o distintos de sqlmap que podrían resolver este
problema específico. Ejemplos de razonamiento esperado: si la
respuesta varía por un token/timestamp dinámico, sugerí --string o
--regexp con un patrón fijo de la respuesta; si es inestabilidad real
del target, sugerí --level/--risk distintos o --technique más
acotado."""

        logger.debug(f"[Gemini] Prompt enviado (suggest_sqlmap_recovery):\n{prompt}")
        start = time.time()
        if self._budget is not None:
            self._budget.consume()
        try:
            from google.genai import types

            response = self._client.models.generate_content(
                model=self.DEFAULT_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    response_mime_type="application/json",
                    response_schema=SqlmapRecovery,
                ),
            )
            latency_ms = round((time.time() - start) * 1000, 1)
            result = response.parsed
            if not isinstance(result, SqlmapRecovery):
                raise ValueError(
                    f"Gemini no devolvió JSON validable contra el schema: "
                    f"{(response.text or '')[:500]!r}"
                )
            recovery = result.model_dump()
            if self._audit_log:
                self._audit_log.record(
                    kind="suggest_sqlmap_recovery",
                    model=self.DEFAULT_MODEL,
                    system_instruction=SYSTEM_INSTRUCTION,
                    prompt=prompt,
                    raw_response=response.text,
                    recovery=recovery,
                    latency_ms=latency_ms,
                    error=None,
                )
            return recovery
        except Exception as e:
            logger.warning(f"Gemini no pudo sugerir recovery (se omite): {e}")
            if self._audit_log:
                self._audit_log.record(
                    kind="suggest_sqlmap_recovery",
                    model=self.DEFAULT_MODEL,
                    system_instruction=SYSTEM_INSTRUCTION,
                    prompt=prompt,
                    raw_response=None,
                    recovery=None,
                    latency_ms=round((time.time() - start) * 1000, 1),
                    error=str(e),
                )
            return {"suggested_flags": [], "reasoning": ""}
