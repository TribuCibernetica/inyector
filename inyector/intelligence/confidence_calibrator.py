"""Calibración de confianza cruzando evidencia de WAF/Stack/ORM.

Las señales de cada detector se calculan de forma aislada, pero no
son independientes en la realidad: si Stack dice "Django" y ORM dice
"django_orm", eso se corrobora mutuamente y la confianza real es
mayor que la de cada señal por separado. Si Stack dice "PHP nativo"
pero ORM dice "django_orm" (imposible — Django es exclusivamente
Python), es una contradicción real que debería bajar la confianza en
vez de mostrarse como si nada.
"""

from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class ConfidenceCalibrator:
    """Ajusta confidence de Stack/ORM cruzando evidencia entre sí."""

    # Lenguaje del stack -> ORMs compatibles con ese lenguaje. Si el
    # ORM detectado no está en el set, hay una contradicción real
    # (no es cuestión de gustos: un proyecto PHP no puede usar
    # SQLAlchemy, que es una librería de Python).
    LANGUAGE_ORM_COMPAT = {
        "python": {"django_orm", "sqlalchemy"},
        "php": {"eloquent"},
        "ruby": {"active_record"},
        "java": {"hibernate"},
        "node": {"sequelize", "prisma"},
    }

    # Framework específico -> ORM "por defecto" de ese framework.
    # Si coinciden, es una corroboración más fuerte que solo compartir
    # lenguaje (ej. Django casi siempre usa django_orm, no cualquier
    # ORM de Python al azar).
    FRAMEWORK_ORM_STRONG_MATCH = {
        "Django": "django_orm",
        "Laravel": "eloquent",
        "Ruby on Rails": "active_record",
        "Spring Boot": "hibernate",
    }

    CONSISTENCY_BONUS = 0.10
    STRONG_MATCH_BONUS = 0.05
    CONTRADICTION_PENALTY = 0.30

    def calibrate(self, recon_data: dict) -> dict:
        """Cruza Stack y ORM y ajusta sus confidences in-place.

        Args:
            recon_data: Diccionario de reconocimiento con 'stack' y
                'orm' (y opcionalmente 'waf', 'graphql').

        Returns:
            El mismo recon_data, con confidences ajustadas y una
            nueva clave 'consistency_notes' explicando los ajustes.
        """
        notes = []
        stack = recon_data.get("stack", {})
        orm = recon_data.get("orm", {})

        language = stack.get("language")
        framework = stack.get("framework")
        orm_name = orm.get("orm")

        has_language_signal = bool(language) and language != "desconocido"
        has_orm_signal = bool(orm_name) and orm_name != "none"

        if has_orm_signal and has_language_signal:
            expected_orms = self.LANGUAGE_ORM_COMPAT.get(language, set())

            if orm_name in expected_orms:
                orm["confidence"] = min(
                    1.0, orm.get("confidence", 0.0) + self.CONSISTENCY_BONUS
                )
                stack["confidence"] = min(
                    1.0, stack.get("confidence", 0.0) + self.CONSISTENCY_BONUS
                )
                notes.append(
                    f"Stack ({framework}/{language}) y ORM ({orm_name}) son "
                    f"consistentes entre sí — confianza ajustada "
                    f"+{self.CONSISTENCY_BONUS:.0%} en ambos"
                )

                if self.FRAMEWORK_ORM_STRONG_MATCH.get(framework) == orm_name:
                    orm["confidence"] = min(
                        1.0, orm["confidence"] + self.STRONG_MATCH_BONUS
                    )
                    notes.append(
                        f"'{orm_name}' es el ORM por defecto de {framework} "
                        f"— confianza ORM +{self.STRONG_MATCH_BONUS:.0%} adicional"
                    )

            elif expected_orms:
                # Solo penalizamos si conocemos los ORMs esperados para
                # ese lenguaje (si no los conocemos, no juzgamos).
                orm["confidence"] = max(
                    0.0, orm.get("confidence", 0.0) - self.CONTRADICTION_PENALTY
                )
                notes.append(
                    f"⚠️ Contradicción: se detectó lenguaje '{language}' pero "
                    f"el ORM '{orm_name}' no es compatible con ese lenguaje "
                    f"— confianza ORM penalizada -{self.CONTRADICTION_PENALTY:.0%} "
                    f"(posible falso positivo de ORMDetector)"
                )
                logger.warning(
                    f"Contradicción stack/orm: {language} vs {orm_name}"
                )

        recon_data["consistency_notes"] = notes
        return recon_data
