"""CLI principal de inyector — SQL Injection Intelligence Tool.

Punto de entrada de la herramienta. La lógica de cada subcomando vive
en inyector/commands/{scan,recon,report,version}.py -- acá solo se
arma el grupo de click y se registran.
"""

import click

from inyector.commands import report as report_cmd
from inyector.commands import scan as scan_cmd
from inyector.commands import version as version_cmd
from inyector.commands import recon as recon_cmd

# Re-exportados por compatibilidad: código/tests que ya referencian
# inyector.cli.create_session (la sesión HTTP compartida, definida en
# commands/common.py) siguen funcionando sin cambios.
from inyector.commands.common import create_session  # noqa: F401


@click.group()
def main():
    """inyector — SQL Injection Intelligence Tool by TribuCibernetica."""
    pass


main.add_command(scan_cmd.scan)
main.add_command(recon_cmd.recon)
main.add_command(report_cmd.report)
main.add_command(version_cmd.version)


if __name__ == "__main__":
    main()
