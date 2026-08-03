"""Comando `version` — versión de inyector y de sqlmap instalado."""

import subprocess

import click

from inyector import __version__
from inyector.commands import common


@click.command(name="version")
def version():
    """Muestra la versión de inyector y sqlmap."""
    common.show_banner()

    common.console.print(f"  [bold]inyector[/bold]  v{__version__}")

    # Intentar obtener versión de sqlmap
    try:
        result = subprocess.run(
            ["sqlmap", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        sqlmap_version = result.stdout.strip() or result.stderr.strip()
        if sqlmap_version:
            for line in sqlmap_version.split("\n"):
                if "sqlmap" in line.lower() or "#" in line:
                    common.console.print(
                        f"  [bold]sqlmap[/bold]   {line.strip()}"
                    )
                    break
        else:
            common.console.print("  [bold]sqlmap[/bold]   instalado")
    except FileNotFoundError:
        common.console.print("  [red]sqlmap    no encontrado[/red]")
    except subprocess.TimeoutExpired:
        common.console.print(
            "  [yellow]sqlmap    timeout al verificar versión[/yellow]"
        )
    except Exception as e:
        common.console.print(f"  [yellow]sqlmap    error: {e}[/yellow]")

    common.console.print()
