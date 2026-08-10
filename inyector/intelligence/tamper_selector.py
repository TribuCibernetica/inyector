"""Módulo de selección inteligente de tamper scripts.

Selecciona los tamper scripts óptimos para sqlmap basándose
en el WAF y ORM detectados durante el reconocimiento.
"""

from typing import Optional
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class TamperSelector:
    """Selecciona tamper scripts óptimos según WAF y ORM detectados."""

    WAF_TAMPER_MAP = {
        "cloudflare": [
            "space2comment", "between", "randomcase",
            "charencode", "charunicodeencode", "greatest",
        ],
        "aws_waf": [
            "greatest", "ifnull2ifisnull", "space2mysqldash",
            "between", "charencode",
        ],
        "modsecurity": [
            "apostrophemask", "base64encode", "charunicodeencode",
            "space2comment", "randomcase", "between",
        ],
        "imperva": [
            "equaltolike", "space2comment", "versionedkeywords",
            "between", "charencode",
        ],
        "akamai": [
            "between", "bluecoat", "charencode",
            "space2comment", "randomcase", "multiplespaces",
        ],
        "wordfence": [
            "between", "space2comment", "randomcase", "charencode",
        ],
        "sucuri": [
            "charencode", "space2comment", "between", "randomcase",
        ],
        "f5": [
            "space2comment", "between", "randomcase",
            "charunicodeencode", "equaltolike",
        ],
        "barracuda": [
            "space2comment", "between", "randomcase",
        ],
        "aws_cloudfront": [
            "greatest", "space2mysqldash", "between", "charencode",
        ],
        "citrix_netscaler": [
            "space2comment", "between", "randomcase", "equaltolike",
        ],
        "fortiweb": [
            "space2comment", "between", "charunicodeencode", "randomcase",
        ],
        "fortigate": [
            "space2comment", "between", "charunicodeencode", "randomcase",
        ],
        "palo_alto": [
            "space2comment", "between", "randomcase", "charencode",
        ],
        "radware": [
            "space2comment", "between", "equaltolike", "randomcase",
        ],
        "distil": [
            "space2comment", "randomcase", "charencode", "between",
        ],
        "perimeterx": [
            "space2comment", "randomcase", "charencode", "between",
        ],
        "stackpath": [
            "space2comment", "between", "charencode", "randomcase",
        ],
        "reblaze": [
            "space2comment", "between", "randomcase", "charencode",
        ],
        "vercel": [
            "space2comment", "between", "randomcase",
        ],
        "zenedge": [
            "space2comment", "between", "randomcase", "charencode",
        ],
        "edgecast": [
            "space2comment", "between", "randomcase",
        ],
        "dotdefender": [
            "apostrophemask", "space2comment", "between", "randomcase",
        ],
        "naxsi": [
            "space2comment", "apostrophemask", "between", "randomcase",
        ],
        "comodo": [
            "space2comment", "between", "randomcase", "charencode",
        ],
        "sitelock": [
            "equaltolike", "space2comment", "between", "charencode",
        ],
        # WAF institucional sin firma de vendor conocida que bloquea
        # SELECT/AND/OR por keyword+espacio con un 302 a un dominio
        # ajeno en vez de un 403 (ver WAFDetector._probe_waf_behavior).
        # scalarfuncbypass ataca la parte que space2comment solo no
        # resuelve: SELECT bloqueado sin importar el delimitador --
        # descubierto y confirmado a mano contra itescam.edu.mx.
        "keyword_sinkhole": [
            "space2comment", "scalarfuncbypass", "between", "randomcase",
        ],
        "none": [],
        "unknown": [
            "space2comment", "scalarfuncbypass", "between", "randomcase",
        ],
    }

    ORM_EXTRA_TAMPERS = {
        "django_orm": ["space2comment"],
        "sqlalchemy": [],
        "hibernate": ["space2comment", "randomcase"],
        "prisma": [],
        "sequelize": [],
        "active_record": ["space2comment"],
        "eloquent": ["space2comment"],
        "none": [],
    }

    def select(self, waf: str, orm: Optional[str] = None,
               technique: Optional[str] = None) -> list[str]:
        """Selecciona tamper scripts basándose en WAF y ORM detectados.

        Args:
            waf: Nombre del WAF detectado.
            orm: Nombre del ORM detectado (opcional).
            technique: Técnica SQLi a utilizar (opcional).

        Returns:
            Lista de tamper scripts ordenados por efectividad.
        """
        logger.info(f"Seleccionando tampers para WAF={waf}, ORM={orm or 'none'}")

        default_tampers = (
            self.WAF_TAMPER_MAP["none"] if waf in (None, "none")
            else self.WAF_TAMPER_MAP["unknown"]
        )
        waf_tampers = self.WAF_TAMPER_MAP.get(waf, default_tampers)
        orm_tampers = self.ORM_EXTRA_TAMPERS.get(orm or "none", [])

        combined = []
        seen = set()
        for tamper in waf_tampers + orm_tampers:
            if tamper not in seen:
                combined.append(tamper)
                seen.add(tamper)

        logger.info(
            f"Tampers seleccionados: {', '.join(combined) if combined else 'ninguno'}"
        )
        return combined

    def to_sqlmap_flag(self, tampers: list[str]) -> str:
        """Convierte la lista de tampers al formato de flag de sqlmap.

        Args:
            tampers: Lista de nombres de tamper scripts.

        Returns:
            String con formato --tamper=script1,script2,script3
        """
        if not tampers:
            return ""
        return f"--tamper={','.join(tampers)}"
