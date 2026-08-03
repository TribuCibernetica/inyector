"""Helpers compartidos entre los subcomandos de inyector.

Nada acá es específico de un solo comando -- create_session, el
banner y la tabla de resumen los usan tanto scan como recon; la
generación de reportes la usan scan y report.
"""

import os
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table

from inyector import __version__
from inyector.reporting.enricher import ResultEnricher
from inyector.reporting.html_report import HTMLReportGenerator
from inyector.reporting.json_report import JSONReportGenerator
from inyector.reporting.markdown_report import MarkdownReportGenerator

# force_terminal=True: ver la nota en sqlmap_runner.py — la detección
# automática de terminal de Rich no es confiable en contenedores
# Linux lanzados desde Docker Desktop en Windows.
console = Console(force_terminal=True)

# Banner ASCII de inyector
BANNER = """
[#00ff88]  ██╗███╗   ██╗██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗
  ██║████╗  ██║╚██╗ ██╔╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██║██╔██╗ ██║ ╚████╔╝ █████╗  ██║        ██║   ██║   ██║██████╔╝
  ██║██║╚██╗██║  ╚██╔╝  ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ██║██║ ╚████║   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝[/]

[dim]  SQL Injection Intelligence Tool v{version}
  by TribuCibernetica — tribucibernetica.com
  Solo para uso en entornos autorizados.[/dim]
"""

# Nivel/risk al que _execute_with_escalation (scan.py) reintenta
# automáticamente cuando sqlmap concluye "no vulnerable" sin haber
# probado el parámetro real -- vive acá porque _show_summary_table
# también lo referencia para el aviso de "auto-escalado".
AUTO_ESCALATE_LEVEL = 5
AUTO_ESCALATE_RISK = 3

# Alias cortos aceptados por --waf → clave canónica usada internamente
# (WAF_TAMPER_MAP, WAFDetector, etc.)
WAF_FORCE_ALIASES = {
    "aws": "aws_waf",
    "modsec": "modsecurity",
}


def _error_suffix(result: dict) -> str:
    """Sufijo visual cuando un detector no pudo verificar (no es lo
    mismo que 'no encontramos nada')."""
    error = result.get("error")
    if not error:
        return ""
    return f" [bold red](⚠️  no verificado: {error})[/bold red]"


def show_banner():
    """Muestra el banner ASCII de inyector."""
    console.print(BANNER.format(version=__version__))


def create_session(cookie: Optional[str] = None, headers: Optional[list] = None,
                   proxy: Optional[str] = None) -> requests.Session:
    """Crea una sesión HTTP con headers realistas.

    Args:
        cookie: Cookies de sesión opcionales.
        headers: Headers adicionales opcionales.
        proxy: Proxy HTTP opcional.

    Returns:
        Sesión HTTP configurada.
    """
    from inyector.utils.headers import HeaderRotator

    session = requests.Session()
    rotator = HeaderRotator()
    session.headers.update(rotator.get_realistic_headers())

    if cookie:
        session.headers["Cookie"] = cookie

    if headers:
        for header in headers:
            if ":" in header:
                key, value = header.split(":", 1)
                session.headers[key.strip()] = value.strip()

    if proxy:
        session.proxies = {
            "http": proxy,
            "https": proxy,
        }

    # Desactivar advertencias SSL para testing
    session.verify = False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Reintentos con backoff ante errores transitorios de red
    # (connection reset, 502/503/504) — importante en corridas largas
    # con --stealth, donde un target real puede tener caídas
    # intermitentes que no significan "no hay nada que encontrar".
    # OJO: 403/406/429 quedan afuera a propósito — esos son la señal
    # misma que waf_detector usa para fingerprinting, reintentarlos
    # los enmascararía como error transitorio.
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    retry_strategy = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def _generate_reports(
    recon_data: dict, enriched: dict,
    output_dir: str, timestamp: str,
    report_format: str,
) -> list[str]:
    """Genera los reportes en los formatos solicitados."""
    paths = []

    # Si no hay datos de sqlmap (modo recon only / --no-sqlmap), igual
    # pasamos por ResultEnricher — si no, un hallazgo real de NoSQLi
    # queda enterrado detrás de un severity 'LIMPIO' solo porque
    # sqlmap (que no soporta NoSQL) nunca corrió.
    if not enriched:
        empty_sqlmap_results = {
            "vulnerable": False,
            "vulnerabilities": [],
            "target_url": recon_data.get("endpoints", {}).get("full_url", ""),
            "dbms": {},
            "databases": [],
        }
        enriched = ResultEnricher().enrich(empty_sqlmap_results, recon_data)

    if report_format in ["json", "all"]:
        json_path = os.path.join(output_dir, f"scan_{timestamp}.json")
        json_gen = JSONReportGenerator()
        json_gen.generate(enriched, json_path)
        paths.append(json_path)

    if report_format in ["html", "all"]:
        html_path = os.path.join(output_dir, f"scan_{timestamp}.html")
        html_gen = HTMLReportGenerator()
        html_gen.generate(enriched, html_path)
        paths.append(html_path)

    if report_format in ["markdown", "all"]:
        md_path = os.path.join(output_dir, f"scan_{timestamp}.md")
        md_gen = MarkdownReportGenerator()
        md_gen.generate(enriched, md_path)
        paths.append(md_path)

    return paths


def _show_summary_table(
    url: str, recon_data: dict,
    enriched: Optional[dict] = None,
    timestamp: str = "",
    elapsed_time: float = 0.0,
    scan_failed: bool = False,
) -> None:
    """Muestra la tabla de resumen final del scan."""
    table = Table(
        title="RESUMEN DEL SCAN",
        title_style="bold #00ff88",
        border_style="#00ff88",
        show_header=False,
        padding=(0, 2),
    )
    table.add_column("Campo", style="bold", width=20)
    table.add_column("Valor", width=45)

    from urllib.parse import urlparse

    parsed_url = urlparse(url)
    table.add_row("Target", parsed_url.netloc or url)

    waf_data = recon_data.get("waf", {})
    table.add_row(
        "WAF detectado",
        waf_data.get("waf", "none") + _error_suffix(waf_data),
    )

    stack_data = recon_data.get("stack", {})
    stack_str = (
        f"{stack_data.get('framework', '?')} + "
        f"{', '.join(stack_data.get('database_hints', ['?']))}"
        f"{_error_suffix(stack_data)}"
    )
    table.add_row("Stack", stack_str)

    orm_data = recon_data.get("orm", {})
    table.add_row(
        "ORM", orm_data.get("orm", "none") + _error_suffix(orm_data),
    )

    if scan_failed:
        table.add_row(
            "Vulnerable",
            "[bold red]⚠️  DESCONOCIDO (sqlmap falló, no confiar en 'NO')[/bold red]",
        )

    if enriched:
        vulnerable = enriched.get("vulnerable", False)
        vuln_text = (
            "[bold green]✅ SÍ[/bold green]"
            if vulnerable
            else "[yellow]❌ NO[/yellow]"
        )
        if not scan_failed:
            table.add_row("Vulnerable", vuln_text)

        if vulnerable:
            vulns = enriched.get("vulnerabilities", [])
            if vulns:
                table.add_row("Tipo SQLi", vulns[0].get("type", "N/A"))
                table.add_row("Parámetro", vulns[0].get("parameter", "N/A"))

            dbms = enriched.get("dbms", {})
            dbms_str = (
                f"{dbms.get('name', 'N/A')} {dbms.get('version', '')}".strip()
            )
            table.add_row("DBMS", dbms_str)

    tampers = recon_data.get("tampers_used", [])
    if tampers:
        table.add_row("Tampers usados", ", ".join(tampers[:4]))

    if enriched and enriched.get("auto_escalated"):
        table.add_row(
            "Auto-escalado",
            f"[yellow]sí — reintentado con level={AUTO_ESCALATE_LEVEL} "
            f"risk={AUTO_ESCALATE_RISK}[/yellow]",
        )

    if elapsed_time > 0:
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        table.add_row("Duración", f"{minutes}m {seconds}s")

    console.print()
    console.print(table)
    console.print()
