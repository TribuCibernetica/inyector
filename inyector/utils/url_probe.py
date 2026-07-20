"""Construcción de URLs de prueba para reconocimiento activo.

Centraliza la lógica de "mutar el valor de un parámetro real de la
URL" que usan WAFDetector, StackDetector y ORMDetector. Mandar el
payload de prueba al parámetro que de verdad se va a atacar (en vez
de inventar uno sintético como 'orm_test=') es lo que hace que estos
detectores realmente disparen el código vulnerable de la aplicación.
"""

from typing import Optional


def build_probe_url(url: str, param: Optional[str],
                     payload: str, fallback_name: str) -> str:
    """Construye una URL de prueba mutando un parámetro real si existe.

    Args:
        url: URL objetivo original.
        param: Nombre del parámetro real a mutar. Si es None, se
            agrega `fallback_name` como parámetro sintético nuevo.
        payload: Valor de prueba a inyectar.
        fallback_name: Nombre a usar si no hay parámetro real conocido.

    Returns:
        URL con el payload de prueba insertado.
    """
    if param and "?" in url:
        base, _, query = url.partition("?")
        new_params = []
        replaced = False
        for pair in query.split("&"):
            if pair.startswith(f"{param}="):
                new_params.append(f"{param}={payload}")
                replaced = True
            else:
                new_params.append(pair)
        if not replaced:
            new_params.append(f"{param}={payload}")
        return f"{base}?{'&'.join(new_params)}"

    if param:
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{param}={payload}"

    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{fallback_name}={payload}"
