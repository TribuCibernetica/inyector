"""Carga de firmas (WAF, ORM, etc.) desde archivos de datos JSON.

Las firmas viven en inyector/data/*.json en vez de hardcodeadas en el
código Python — así se pueden actualizar o ampliar sin tocar lógica,
y eventualmente sincronizar contra bases de firmas públicas (ej.
wafw00f) sin necesidad de un release nuevo.
"""

import json
import os
from functools import lru_cache

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@lru_cache(maxsize=None)
def load_signatures(filename: str) -> dict:
    """Carga y cachea un archivo de firmas JSON.

    Args:
        filename: Nombre del archivo dentro de inyector/data/
            (ej. 'waf_signatures.json').

    Returns:
        Diccionario con las firmas parseadas.
    """
    path = os.path.join(DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
