"""Comandos del CLI de inyector — uno por subcomando de click.

Extraído de un cli.py monolítico de ~1500 líneas para que cada
subcomando (scan/recon/report/version) se pueda leer y modificar sin
tener que cargar el resto en la cabeza. common.py tiene lo que
comparten más de un comando (sesión HTTP, banner, tabla de resumen,
generación de reportes).
"""
