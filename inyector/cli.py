"""CLI principal de inyector — SQL Injection Intelligence Tool.

Punto de entrada de la herramienta. Implementa todos los comandos
y orquesta el flujo completo de reconocimiento → inteligencia → ejecución → reporte.
"""

import os
import sys
import time
import subprocess
from datetime import datetime

import click
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from inyector import __version__
from inyector.utils.logger import configure_logging, get_logger
from inyector.utils.headers import HeaderRotator
from inyector.utils.stealth import StealthEngine
from inyector.recon.waf_detector import WAFDetector
from inyector.recon.stack_detector import StackDetector
from inyector.recon.orm_detector import ORMDetector
from inyector.recon.graphql_detector import GraphQLDetector
from inyector.recon.nosqli_detector import NoSQLiDetector
from inyector.recon.endpoint_mapper import EndpointMapper
from inyector.intelligence.tamper_selector import TamperSelector
from inyector.intelligence.timing_calculator import TimingCalculator
from inyector.intelligence.technique_selector import TechniqueSelector
from inyector.intelligence.command_builder import CommandBuilder
from inyector.intelligence.confidence_calibrator import ConfidenceCalibrator
from inyector.utils.session_store import SessionStore
from inyector.executor.sqlmap_runner import SqlmapRunner
from inyector.reporting.parser import SqlmapOutputParser
from inyector.reporting.enricher import ResultEnricher
from inyector.reporting.html_report import HTMLReportGenerator
from inyector.reporting.json_report import JSONReportGenerator
from inyector.reporting.markdown_report import MarkdownReportGenerator

console = Console()
logger = get_logger(__name__)

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


def _error_suffix(result: dict) -> str:
    """Sufijo visual cuando un detector no pudo verificar (no es lo
    mismo que 'no encontramos nada')."""
    error = result.get("error")
    if not error:
        return ""
    return f" [bold red](⚠️  no verificado: {error})[/bold red]"


# Alias cortos aceptados por --waf → clave canónica usada internamente
# (WAF_TAMPER_MAP, WAFDetector, etc.)
WAF_FORCE_ALIASES = {
    "aws": "aws_waf",
    "modsec": "modsecurity",
}


def show_banner():
    """Muestra el banner ASCII de inyector."""
    console.print(BANNER.format(version=__version__))


def create_session(cookie: str = None, headers: list = None,
                   proxy: str = None) -> requests.Session:
    """Crea una sesión HTTP con headers realistas.

    Args:
        cookie: Cookies de sesión opcionales.
        headers: Headers adicionales opcionales.
        proxy: Proxy HTTP opcional.

    Returns:
        Sesión HTTP configurada.
    """
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

    return session


@click.group()
def main():
    """inyector — SQL Injection Intelligence Tool by TribuCibernetica."""
    pass


def _run_recon_phase(url, param, method, data, waf, session,
                      stealth_mode, stealth_engine, graphql, nosql, console):
    """Corre la fase 1 (reconocimiento) completa y devuelve recon_data.

    Extraída a función propia para poder saltarla limpiamente cuando
    --resume reutiliza una sesión de recon ya guardada.
    """
    recon_data = {}

    # Mapear endpoint ANTES del resto del recon: así WAF/Stack/ORM
    # pueden mandar sus payloads de prueba al parámetro real que se va
    # a atacar, en vez de a uno sintético que la app probablemente
    # ignora (bug encontrado: los detectores de Stack/ORM mandaban su
    # payload a un parámetro inventado tipo 'orm_test=' que casi
    # ninguna app real refleja).
    mapper = EndpointMapper()
    endpoint_map = mapper.map_parameters(url, method=method, data=data)
    recon_data["endpoints"] = endpoint_map

    effective_param = param
    if not effective_param and endpoint_map["injectable_params"]:
        effective_param = endpoint_map["injectable_params"][0]["name"]
        console.print(
            f"[dim]  (sin -p explícito, usando '{effective_param}' "
            f"como parámetro prioritario detectado)[/dim]"
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # 1.1 Detectar WAF
        task = progress.add_task("[cyan]Detectando WAF...", total=None)
        waf_detector = WAFDetector()
        if waf:
            # Los alias cortos del flag --waf (aws, modsec) no coinciden
            # con las claves canónicas que usa el resto del pipeline
            # (aws_waf, modsecurity) — hay que normalizarlos aquí.
            waf_result = {
                "waf": WAF_FORCE_ALIASES.get(waf.lower(), waf.lower()),
                "confidence": 1.0,
                "evidence": ["Forzado por usuario"],
            }
        else:
            waf_result = waf_detector.detect(url, session)
        recon_data["waf"] = waf_result
        progress.update(
            task,
            description=(
                f"[green]✓ WAF: {waf_result['waf']} "
                f"(confianza: {waf_result['confidence']:.0%})"
            ),
        )
        progress.remove_task(task)
        console.print(
            f"  [#00ff88]→[/] WAF detectado: [bold]{waf_result['waf']}[/bold] "
            f"(confianza: {waf_result['confidence']:.0%})"
            f"{_error_suffix(waf_result)}"
        )

        if stealth_mode:
            stealth_engine.human_delay(500, 1500)

        # 1.2 Detectar Stack
        task = progress.add_task("[cyan]Detectando stack tecnológico...", total=None)
        stack_detector = StackDetector()
        stack_result = stack_detector.detect(url, session, param=effective_param)
        recon_data["stack"] = stack_result
        progress.update(
            task,
            description=(
                f"[green]✓ Stack: {stack_result['framework']} "
                f"({stack_result['language']})"
            ),
        )
        progress.remove_task(task)
        console.print(
            f"  [#00ff88]→[/] Stack: [bold]{stack_result['framework']}[/bold] "
            f"+ {', '.join(stack_result['database_hints']) or 'BD desconocida'}"
            f"{_error_suffix(stack_result)}"
        )

        if stealth_mode:
            stealth_engine.human_delay(500, 1500)

        # 1.3 Detectar ORM
        task = progress.add_task("[cyan]Detectando ORM...", total=None)
        orm_detector = ORMDetector()
        orm_result = orm_detector.detect(url, session, param=effective_param)
        recon_data["orm"] = orm_result
        progress.update(
            task, description=f"[green]✓ ORM: {orm_result['orm']}",
        )
        progress.remove_task(task)
        orm_display = orm_result["orm"]
        if orm_result.get("escape_hatches"):
            orm_display += (
                f" (escape hatches: {', '.join(orm_result['escape_hatches'])})"
            )
        console.print(
            f"  [#00ff88]→[/] ORM: [bold]{orm_display}[/bold]"
            f"{_error_suffix(orm_result)}"
        )

        if stealth_mode:
            stealth_engine.human_delay(500, 1500)

        # 1.4 Detectar GraphQL (si se solicitó)
        graphql_data = {
            "endpoints": [],
            "engine": "unknown",
            "introspection_enabled": False,
            "injectable_args": [],
        }
        if graphql:
            task = progress.add_task(
                "[cyan]Buscando endpoints GraphQL...", total=None,
            )
            gql_detector = GraphQLDetector()
            endpoints = gql_detector.detect_endpoints(url, session)
            graphql_data["endpoints"] = endpoints

            if endpoints:
                engine_result = gql_detector.fingerprint_engine(
                    endpoints[0], session,
                )
                graphql_data["engine"] = engine_result["engine"]
                graphql_data["engine_confidence"] = engine_result["confidence"]

                intro_result = gql_detector.check_introspection(
                    endpoints[0], session,
                )
                graphql_data["introspection_enabled"] = intro_result["enabled"]

                if intro_result["enabled"]:
                    injectable = gql_detector.find_injectable_args(intro_result)
                    graphql_data["injectable_args"] = injectable

            progress.update(
                task,
                description=(
                    f"[green]✓ GraphQL: {len(endpoints)} endpoint(s) encontrado(s)"
                ),
            )
            progress.remove_task(task)

            for ep in endpoints:
                console.print(
                    f"  [#00ff88]→[/] Endpoint GraphQL: [bold]{ep}[/bold]"
                )
            if endpoints and graphql_data["engine"] != "unknown":
                console.print(
                    f"  [#00ff88]→[/] Motor GraphQL: "
                    f"[bold]{graphql_data['engine']}[/bold] "
                    f"(confianza: {graphql_data.get('engine_confidence', 0):.0%})"
                )
            if not endpoints:
                console.print(
                    "  [dim]→ No se encontraron endpoints GraphQL[/dim]"
                )

        recon_data["graphql"] = graphql_data

    # 1.5 Detectar NoSQL injection (MongoDB) — sqlmap NO soporta
    # NoSQL, así que esto corre siempre como detección propia,
    # independiente de que después se ejecute sqlmap o no.
    nosqli_data = {
        "engine": "unknown",
        "operator_injection": {"vulnerable": False},
        "where_injection": {"vulnerable": False},
    }
    if nosql:
        task_param = effective_param or "id"
        nosqli_detector = NoSQLiDetector()

        engine_fp = nosqli_detector.fingerprint_engine(url, session)
        nosqli_data["engine"] = engine_fp["engine"]

        op_result = nosqli_detector.detect_operator_injection(
            url, session, param=task_param, method=method, data=data,
        )
        nosqli_data["operator_injection"] = op_result

        where_result = nosqli_detector.detect_where_injection(
            url, session, param=task_param,
        )
        nosqli_data["where_injection"] = where_result

        console.print(
            f"  [#00ff88]→[/] NoSQL: motor [bold]{engine_fp['engine']}[/bold]"
        )
        if op_result["vulnerable"]:
            console.print(
                f"  [bold red]→ Operator injection confirmada[/bold red] "
                f"en '{task_param}' (vector: {op_result['vector']})"
            )
        if where_result["vulnerable"]:
            console.print(
                f"  [bold red]→ $where injection confirmada[/bold red] "
                f"en '{task_param}' (técnica: {where_result['technique']})"
            )
        if not op_result["vulnerable"] and not where_result["vulnerable"]:
            console.print("  [dim]→ Sin NoSQL injection detectada[/dim]")

    recon_data["nosqli"] = nosqli_data

    # Cruzar Stack+ORM para calibrar confianza antes de que la fase
    # de inteligencia decida tampers/técnica en base a esos valores.
    calibrator = ConfidenceCalibrator()
    calibrator.calibrate(recon_data)
    for note in recon_data.get("consistency_notes", []):
        console.print(f"  [dim]ℹ {note}[/dim]")
    return recon_data


@main.command()
@click.option("-u", "--url", required=True, help="URL objetivo")
@click.option("-p", "--param", default=None, help="Parámetro específico a testear")
@click.option("--method", default="GET", help="Método HTTP: GET o POST (default: GET)")
@click.option("--data", default=None, help="Data para POST request")
@click.option("--cookie", default=None, help="Cookies de sesión")
@click.option("--header", multiple=True, help="Headers adicionales (múltiples)")
@click.option("--stealth", is_flag=True, default=False, help="Modo sigilo máximo")
@click.option("--fast", is_flag=True, default=False, help="Sin modo sigilo")
@click.option("--waf", default=None,
              type=click.Choice([
                  "cloudflare", "aws", "modsec", "imperva", "akamai",
                  "wordfence", "sucuri", "f5", "barracuda",
                  "aws_cloudfront", "citrix_netscaler", "fortiweb",
                  "fortigate", "palo_alto", "radware", "distil",
                  "perimeterx", "stackpath", "reblaze", "vercel",
                  "zenedge", "edgecast", "dotdefender", "naxsi",
                  "comodo", "sitelock", "none",
              ], case_sensitive=False),
              help="Forzar WAF específico")
@click.option("--technique", default=None, help="Forzar técnica SQLi (B/E/U/S/T/Q)")
@click.option("--tamper", default=None, help="Tamper scripts adicionales")
@click.option("--threads", default=3, help="Threads para sqlmap (default: 3)")
@click.option("--level", default=2, type=click.IntRange(1, 5),
              help="Level sqlmap 1-5 (default: 2)")
@click.option("--risk", default=1, type=click.IntRange(1, 3),
              help="Risk sqlmap 1-3 (default: 1)")
@click.option("--output-dir", default=None, help="Directorio de reportes")
@click.option("--format", "report_format", default="all",
              type=click.Choice(["html", "json", "markdown", "all"], case_sensitive=False),
              help="Formato del reporte (default: all)")
@click.option("--graphql", is_flag=True, default=False, help="Activar módulo GraphQL")
@click.option("--nosql", is_flag=True, default=False,
              help="Activar detección de NoSQL injection (MongoDB): "
                   "operator injection ($ne/$eq) y $where injection. "
                   "sqlmap no soporta NoSQL, así que esto corre con motor propio.")
@click.option("--websocket", is_flag=True, default=False, help="Activar módulo WebSocket")
@click.option("--no-sqlmap", is_flag=True, default=False, help="Solo reconocimiento")
@click.option("--proxy", default=None, help="Proxy HTTP")
@click.option("--tor", is_flag=True, default=False, help="Enrutar por Tor")
@click.option("--resume", is_flag=True, default=False,
              help="Reusar el recon guardado de un scan anterior al mismo target "
                   "(evita repetir peticiones de WAF/Stack/ORM/GraphQL)")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Output detallado")
@click.option("-q", "--quiet", is_flag=True, default=False, help="Solo resultados finales")
def scan(url, param, method, data, cookie, header, stealth, fast,
         waf, technique, tamper, threads, level, risk, output_dir,
         report_format, graphql, nosql, websocket, no_sqlmap, proxy, tor,
         resume, verbose, quiet):
    """Ejecuta un scan completo de SQL Injection."""
    show_banner()
    configure_logging(verbose=verbose, quiet=quiet)

    # Configurar directorio de output
    output_dir = output_dir or os.environ.get(
        "INYECTOR_REPORTS_DIR", "/app/reports"
    )
    os.makedirs(output_dir, exist_ok=True)

    # Timestamp para nombres de archivo
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determinar modo stealth
    stealth_mode = True  # Default
    if fast:
        stealth_mode = False
    if stealth:
        stealth_mode = True

    # Proxy Tor
    if tor:
        proxy = proxy or "socks5://127.0.0.1:9050"

    console.print("[bold #00ff88][*] Iniciando reconocimiento...[/bold #00ff88]\n")

    # Crear sesión HTTP
    session = create_session(cookie=cookie, headers=list(header), proxy=proxy)

    # Motor de stealth
    stealth_engine = StealthEngine()

    # ════════════════════════════════════════════
    # FASE 1: RECONOCIMIENTO
    # ════════════════════════════════════════════
    session_store = SessionStore()
    recon_data = None
    if resume:
        recon_data = session_store.load(output_dir, url, param, method)
        if recon_data:
            console.print(
                "[bold #00ff88][*] Reusando recon guardado de un scan "
                "anterior contra este target...[/bold #00ff88]\n"
            )
        else:
            console.print(
                "[yellow]--resume solicitado pero no hay sesión "
                "guardada para este target — corriendo "
                "reconocimiento completo[/yellow]\n"
            )

    if recon_data is None:
        recon_data = _run_recon_phase(
            url, param, method, data, waf, session,
            stealth_mode, stealth_engine, graphql, nosql, console,
        )
        session_store.save(output_dir, url, param, method, recon_data)

    console.print()

    # Si es solo reconocimiento, terminar aquí
    if no_sqlmap:
        console.print(
            "[yellow]⚠️  Modo --no-sqlmap: solo reconocimiento[/yellow]\n"
        )
        _show_summary_table(url, recon_data, None, timestamp)
        _generate_reports(recon_data, {}, output_dir, timestamp, report_format)
        return

    # ════════════════════════════════════════════
    # FASE 2: INTELIGENCIA
    # ════════════════════════════════════════════
    console.print(
        "[bold #00ff88][*] Fase de inteligencia...[/bold #00ff88]\n"
    )

    # 2.1 Seleccionar tamper scripts
    tamper_selector = TamperSelector()
    selected_tampers = tamper_selector.select(
        waf=recon_data["waf"]["waf"],
        orm=recon_data["orm"]["orm"],
    )
    if tamper:
        user_tampers = [t.strip() for t in tamper.split(",")]
        for t in user_tampers:
            if t not in selected_tampers:
                selected_tampers.append(t)

    recon_data["tampers_used"] = selected_tampers
    console.print(
        f"  [#00ff88]→[/] Tampers seleccionados: "
        f"[bold]{', '.join(selected_tampers) if selected_tampers else 'ninguno'}[/bold]"
    )

    # 2.2 Calcular timing
    timing_calc = TimingCalculator(stealth_mode=stealth_mode)
    baseline = timing_calc.measure_baseline(url, session)
    timing_result = timing_calc.calculate_delay(baseline, recon_data["waf"]["waf"])
    console.print(
        f"  [#00ff88]→[/] Baseline: {baseline:.0f}ms, "
        f"Delay configurado: {timing_result['delay']}s"
    )

    # 2.3 Construir comando sqlmap
    scan_config = {
        "url": url,
        "param": param,
        "method": method,
        "data": data,
        "cookie": cookie,
        "headers": list(header),
        "waf": recon_data["waf"],
        "stack": recon_data["stack"],
        "orm": recon_data["orm"],
        "timing": timing_result,
        "tampers": selected_tampers,
        "technique": technique,
        "level": level,
        "risk": risk,
        "threads": threads,
        "proxy": proxy,
        "output_dir": output_dir,
        "stealth": stealth_mode,
    }

    builder = CommandBuilder()
    sqlmap_command = builder.build(scan_config)

    if verbose:
        console.print(f"\n  [dim]Comando: {sqlmap_command}[/dim]")

    console.print()

    # ════════════════════════════════════════════
    # FASE 3: EJECUCIÓN
    # ════════════════════════════════════════════
    console.print(
        "[bold #00ff88][*] Ejecutando sqlmap con configuración "
        "optimizada...[/bold #00ff88]\n"
    )

    start_time = time.time()
    runner = SqlmapRunner(verbose=verbose)
    execution_result = runner.run(sqlmap_command, output_dir)
    elapsed_time = time.time() - start_time

    scan_failed = not execution_result.get("success", False)
    if scan_failed:
        failure_reason = execution_result.get("failure_reason")
        if failure_reason:
            console.print(
                f"\n[bold red]⚠️  sqlmap nunca llegó a probar SQLi "
                f"realmente: '{failure_reason}'. El resultado "
                f"'no vulnerable' NO es confiable.[/bold red]"
            )
        else:
            console.print(
                f"\n[bold red]⚠️  sqlmap terminó con código de salida "
                f"{execution_result.get('exit_code')} — el resultado "
                f"'no vulnerable' NO es confiable.[/bold red]"
            )
        stderr_tail = (execution_result.get("stderr") or "").strip()
        if stderr_tail:
            console.print(f"[red]{stderr_tail[-1500:]}[/red]")
        console.print(
            "[yellow]Vuelve a correr el scan con -v para ver el output "
            "completo de sqlmap y diagnosticar la causa.[/yellow]\n"
        )

    console.print()

    # ════════════════════════════════════════════
    # FASE 4: REPORTE
    # ════════════════════════════════════════════
    console.print(
        "[bold #00ff88][*] Generando reportes...[/bold #00ff88]\n"
    )

    # Parsear resultados
    parser = SqlmapOutputParser()
    parsed_results = parser.parse(execution_result["stdout"], output_dir)

    # Enriquecer resultados
    enricher = ResultEnricher()
    enriched = enricher.enrich(parsed_results, recon_data)

    # Generar reportes
    report_paths = _generate_reports(
        recon_data, enriched, output_dir, timestamp, report_format,
    )

    for path in report_paths:
        ext = os.path.splitext(path)[1].upper().lstrip(".")
        console.print(f"  [green]✅ {ext}: {path}[/green]")

    console.print()

    # Mostrar resumen
    _show_summary_table(
        url, recon_data, enriched, timestamp, elapsed_time, scan_failed,
    )


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
    enriched: dict = None,
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

    if elapsed_time > 0:
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        table.add_row("Duración", f"{minutes}m {seconds}s")

    console.print()
    console.print(table)
    console.print()


@main.command()
@click.option("-u", "--url", required=True, help="URL objetivo")
@click.option("--graphql", is_flag=True, default=False,
              help="Activar módulo GraphQL")
@click.option("--nosql", is_flag=True, default=False,
              help="Activar detección de NoSQL injection (MongoDB)")
@click.option("--websocket", is_flag=True, default=False,
              help="Activar módulo WebSocket")
@click.option("--cookie", default=None, help="Cookies de sesión")
@click.option("--header", multiple=True, help="Headers adicionales")
@click.option("--proxy", default=None, help="Proxy HTTP")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Output detallado")
def recon(url, graphql, nosql, websocket, cookie, header, proxy, verbose):
    """Ejecuta solo el reconocimiento sin sqlmap."""
    show_banner()
    configure_logging(verbose=verbose)

    console.print(
        "[bold #00ff88][*] Modo reconocimiento (sin sqlmap)[/bold #00ff88]\n"
    )

    session = create_session(
        cookie=cookie, headers=list(header), proxy=proxy,
    )

    recon_data = {}

    # Endpoints — se mapea primero para poder mandar los payloads de
    # Stack/ORM al parámetro real en vez de a uno sintético.
    mapper = EndpointMapper()
    endpoint_map = mapper.map_parameters(url)
    recon_data["endpoints"] = endpoint_map
    effective_param = (
        endpoint_map["injectable_params"][0]["name"]
        if endpoint_map["injectable_params"] else None
    )

    # WAF
    console.print("  [cyan]Detectando WAF...[/cyan]")
    waf_result = WAFDetector().detect(url, session)
    recon_data["waf"] = waf_result
    console.print(
        f"  [#00ff88]→[/] WAF: [bold]{waf_result['waf']}[/bold] "
        f"({waf_result['confidence']:.0%}){_error_suffix(waf_result)}"
    )

    # Stack
    console.print("  [cyan]Detectando stack...[/cyan]")
    stack_result = StackDetector().detect(url, session, param=effective_param)
    recon_data["stack"] = stack_result
    console.print(
        f"  [#00ff88]→[/] Stack: [bold]{stack_result['framework']}[/bold]"
        f"{_error_suffix(stack_result)}"
    )

    # ORM
    console.print("  [cyan]Detectando ORM...[/cyan]")
    orm_result = ORMDetector().detect(url, session, param=effective_param)
    recon_data["orm"] = orm_result
    console.print(
        f"  [#00ff88]→[/] ORM: [bold]{orm_result['orm']}[/bold]"
        f"{_error_suffix(orm_result)}"
    )

    # GraphQL
    if graphql:
        console.print("  [cyan]Buscando endpoints GraphQL...[/cyan]")
        gql = GraphQLDetector()
        endpoints = gql.detect_endpoints(url, session)
        graphql_data = {
            "endpoints": endpoints,
            "engine": "unknown",
            "introspection_enabled": False,
            "injectable_args": [],
        }

        if endpoints:
            engine_result = gql.fingerprint_engine(endpoints[0], session)
            graphql_data["engine"] = engine_result["engine"]
            graphql_data["engine_confidence"] = engine_result["confidence"]

            intro = gql.check_introspection(endpoints[0], session)
            graphql_data["introspection_enabled"] = intro["enabled"]
            if intro["enabled"]:
                graphql_data["injectable_args"] = (
                    gql.find_injectable_args(intro)
                )

        recon_data["graphql"] = graphql_data
        console.print(
            f"  [#00ff88]→[/] GraphQL: [bold]{len(endpoints)} endpoint(s)[/bold]"
        )
        if endpoints and graphql_data["engine"] != "unknown":
            console.print(
                f"  [#00ff88]→[/] Motor GraphQL: "
                f"[bold]{graphql_data['engine']}[/bold] "
                f"(confianza: {graphql_data.get('engine_confidence', 0):.0%})"
            )

    # NoSQL injection (MongoDB) — motor propio, sqlmap no lo soporta
    nosqli_data = {
        "engine": "unknown",
        "operator_injection": {"vulnerable": False},
        "where_injection": {"vulnerable": False},
    }
    if nosql:
        console.print("  [cyan]Buscando NoSQL injection...[/cyan]")
        task_param = effective_param or "id"
        nosqli_detector = NoSQLiDetector()

        engine_fp = nosqli_detector.fingerprint_engine(url, session)
        nosqli_data["engine"] = engine_fp["engine"]

        op_result = nosqli_detector.detect_operator_injection(
            url, session, param=task_param, method="GET",
        )
        nosqli_data["operator_injection"] = op_result

        where_result = nosqli_detector.detect_where_injection(
            url, session, param=task_param,
        )
        nosqli_data["where_injection"] = where_result

        console.print(f"  [#00ff88]→[/] NoSQL: motor [bold]{engine_fp['engine']}[/bold]")
        if op_result["vulnerable"]:
            console.print(
                f"  [bold red]→ Operator injection confirmada[/bold red] "
                f"en '{task_param}'"
            )
        if where_result["vulnerable"]:
            console.print(
                f"  [bold red]→ $where injection confirmada[/bold red] "
                f"en '{task_param}'"
            )

    recon_data["nosqli"] = nosqli_data

    ConfidenceCalibrator().calibrate(recon_data)
    for note in recon_data.get("consistency_notes", []):
        console.print(f"  [dim]ℹ {note}[/dim]")

    console.print()
    _show_summary_table(url, recon_data)


@main.command()
@click.option("--input", "input_file", required=True,
              help="Archivo JSON de resultados")
@click.option("--format", "report_format", default="html",
              type=click.Choice(["html", "json", "markdown", "all"]),
              help="Formato del reporte")
@click.option("--output-dir", default=None, help="Directorio de salida")
def report(input_file, report_format, output_dir):
    """Genera un reporte a partir de resultados existentes."""
    show_banner()
    configure_logging()

    import json

    if not os.path.exists(input_file):
        console.print(
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
        console.print(f"  [green]✅ HTML: {html_path}[/green]")

    if report_format in ["json", "all"]:
        json_path = os.path.join(output_dir, f"report_{timestamp}.json")
        JSONReportGenerator().generate(data, json_path)
        console.print(f"  [green]✅ JSON: {json_path}[/green]")

    if report_format in ["markdown", "all"]:
        md_path = os.path.join(output_dir, f"report_{timestamp}.md")
        MarkdownReportGenerator().generate(data, md_path)
        console.print(f"  [green]✅ MD: {md_path}[/green]")


@main.command()
def version():
    """Muestra la versión de inyector y sqlmap."""
    show_banner()

    console.print(f"  [bold]inyector[/bold]  v{__version__}")

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
                    console.print(
                        f"  [bold]sqlmap[/bold]   {line.strip()}"
                    )
                    break
        else:
            console.print("  [bold]sqlmap[/bold]   instalado")
    except FileNotFoundError:
        console.print("  [red]sqlmap    no encontrado[/red]")
    except subprocess.TimeoutExpired:
        console.print(
            "  [yellow]sqlmap    timeout al verificar versión[/yellow]"
        )
    except Exception as e:
        console.print(f"  [yellow]sqlmap    error: {e}[/yellow]")

    console.print()


if __name__ == "__main__":
    main()
