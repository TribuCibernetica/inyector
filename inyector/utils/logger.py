"""Módulo de logging centralizado para inyector.

Proporciona un logger consistente basado en Rich
para todas las salidas de la herramienta.
"""

import logging
from rich.logging import RichHandler
from rich.console import Console

# Consola global compartida
console = Console()

# Configuración del nivel de logging
_log_level = logging.INFO
_configured = False


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configura el nivel de logging global.

    Args:
        verbose: Si es True, muestra mensajes DEBUG.
        quiet: Si es True, solo muestra errores.
    """
    global _log_level, _configured

    if quiet:
        _log_level = logging.ERROR
    elif verbose:
        _log_level = logging.DEBUG
    else:
        _log_level = logging.INFO

    # Configurar el handler de Rich
    logging.basicConfig(
        level=_log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                show_time=False,
                show_path=False,
                markup=True,
                rich_tracebacks=True,
            )
        ],
        force=True,
    )

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Obtiene un logger configurado con Rich.

    Args:
        name: Nombre del módulo (típicamente __name__).

    Returns:
        Logger configurado.
    """
    global _configured

    if not _configured:
        configure_logging()

    logger = logging.getLogger(name)
    return logger
