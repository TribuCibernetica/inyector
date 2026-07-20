"""Comparación tolerante de respuestas HTTP.

Misma lógica que usa sqlmap para boolean-blind: dos respuestas se
consideran "iguales" si tienen el mismo status code y una longitud de
body razonablemente parecida (no exacta, porque muchas páginas
incluyen contenido dinámico irrelevante como timestamps o contadores).
"""

from typing import Optional


def responses_similar(resp_a, resp_b) -> bool:
    """Compara dos respuestas HTTP de forma tolerante.

    Args:
        resp_a: Primera respuesta (objeto con .status_code y .text),
            o None si la petición falló.
        resp_b: Segunda respuesta, misma forma.

    Returns:
        True si se consideran equivalentes.
    """
    if resp_a is None or resp_b is None:
        return False
    if resp_a.status_code != resp_b.status_code:
        return False

    len_a, len_b = len(resp_a.text), len(resp_b.text)
    if len_a == 0 and len_b == 0:
        return True

    diff = abs(len_a - len_b)
    return diff <= max(5, 0.02 * max(len_a, len_b))
