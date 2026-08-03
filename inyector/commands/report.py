"""Comando `report` — genera un reporte a partir de resultados JSON
de un scan previo, sin volver a correr nada contra el target."""

import json
import os
import sys
from datetime import datetime

import click

from inyector.commands import common
from inyector.utils.logger import configure_logging
from inyector.reporting.html_report import HTMLReportGenerator
from inyector.reporting.json_report import JSONReportGenerator
from inyector.reporting.markdown_report import MarkdownReportGenerator


@click.command(name="report")
@click.option("--input", "input_file", required=True,
              help="Archivo JSON de resultados")
@click.option("--format", "report_format", default="html",
              type=click.Choice(["html", "json", "markdown", "all"]),
              help="Formato del reporte")
@click.option("--output-dir", default=None, help="Directorio de salida")
def report(input_file, report_format, output_dir):
    """Genera un reporte a partir de resultados existentes."""
    common.show_banner()
    configure_logging()

    if not os.path.exists(input_file):
        common.console.print(
            f"[red]Error: Archivo no encontrado: {input_file}[/red]"
        )
        sys.exit(1)

    with open(input_file, "r") as f:
        data = json.load(f)

    output_dir = output_dir or os.environ.get(
        "INYECTOR_REPORTS_DIR", "/app/reports",
    )
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if report_format in ["html", "all"]:
        html_path = os.path.join(output_dir, f"report_{timestamp}.html")
        HTMLReportGenerator().generate(data, html_path)
        common.console.print(f"  [green]✅ HTML: {html_path}[/green]")

    if report_format in ["json", "all"]:
        json_path = os.path.join(output_dir, f"report_{timestamp}.json")
        JSONReportGenerator().generate(data, json_path)
        common.console.print(f"  [green]✅ JSON: {json_path}[/green]")

    if report_format in ["markdown", "all"]:
        md_path = os.path.join(output_dir, f"report_{timestamp}.md")
        MarkdownReportGenerator().generate(data, md_path)
        common.console.print(f"  [green]✅ MD: {md_path}[/green]")
