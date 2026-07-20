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
from typing import Optional

from pydantic import BaseModel, Field

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


class AIAssistant:
    """Wrapper del cliente de Gemini para sugerencias puntuales de SQLi."""

    DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    def __init__(self, api_key: Optional[str] = None):
        """Inicializa el cliente de Gemini.

        Args:
            api_key: API key de Gemini. Si se omite, se busca en la
                variable de entorno GEMINI_API_KEY.

        Raises:
            ValueError: si no hay API key disponible por ningún lado.
        """
        api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY no configurada — --ai-assist requiere una "
                "API key de Gemini (ver README: 'Asistente de IA (opcional)')"
            )

        from google import genai
        self._client = genai.Client(api_key=api_key)

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

        try:
            interaction = self._client.interactions.create(
                model=self.DEFAULT_MODEL,
                system_instruction=SYSTEM_INSTRUCTION,
                input=prompt,
                response_format={
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": PayloadSuggestions.model_json_schema(),
                },
            )
            result = PayloadSuggestions.model_validate_json(interaction.output_text)
            logger.info(
                f"Gemini sugirió {len(result.suggestions)} payload(s) avanzado(s)"
            )
            return [s.model_dump() for s in result.suggestions]
        except Exception as e:
            logger.warning(f"Gemini no pudo sugerir payloads (se omite): {e}")
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

        try:
            interaction = self._client.interactions.create(
                model=self.DEFAULT_MODEL,
                system_instruction=SYSTEM_INSTRUCTION,
                input=prompt,
                response_format={
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": SqlmapRecovery.model_json_schema(),
                },
            )
            result = SqlmapRecovery.model_validate_json(interaction.output_text)
            return result.model_dump()
        except Exception as e:
            logger.warning(f"Gemini no pudo sugerir recovery (se omite): {e}")
            return {"suggested_flags": [], "reasoning": ""}
