"""Comando `scan` — flujo completo de reconocimiento → inteligencia →
ejecución de sqlmap → asistencia de IA opcional → reporte.

El comando en sí (la función `scan`) solo resuelve qué targets tocan
(uno solo, --crawl-all, o --targets-file) y delega cada uno a
_run_target_scan. Todo lo demás en este archivo son las fases
internas de ese flujo por-target.
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Optional

import click
import requests
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from inyector.commands import common
from inyector.utils.logger import configure_logging
from inyector.utils.stealth import StealthEngine
from inyector.recon.waf_detector import WAFDetector
from inyector.recon.stack_detector import StackDetector
from inyector.recon.orm_detector import ORMDetector
from inyector.recon.graphql_detector import GraphQLDetector
from inyector.recon.crawler import Crawler
from inyector.recon.nosqli_detector import NoSQLiDetector
from inyector.recon.endpoint_mapper import EndpointMapper
from inyector.intelligence.tamper_selector import TamperSelector
from inyector.intelligence.timing_calculator import TimingCalculator
from inyector.intelligence.command_builder import CommandBuilder
from inyector.intelligence.confidence_calibrator import ConfidenceCalibrator
from inyector.intelligence.knowledge_base import KnowledgeBase
from inyector.intelligence.ai_audit_log import AIAuditLog
from inyector.intelligence.ai_assistant import AICallBudget
from inyector.intelligence.payload_verifier import verify_payload
from inyector.utils.session_store import SessionStore
from inyector.executor.sqlmap_runner import SqlmapRunner
from inyector.reporting.parser import SqlmapOutputParser
from inyector.reporting.enricher import ResultEnricher


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
                "waf": common.WAF_FORCE_ALIASES.get(waf.lower(), waf.lower()),
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
            f"{common._error_suffix(waf_result)}"
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
            f"{common._error_suffix(stack_result)}"
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
            f"{common._error_suffix(orm_result)}"
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


@click.command(name="scan")
@click.option("-u", "--url", default=None,
              help="URL objetivo. Requerido salvo que se use --targets-file.")
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
@click.option("--crawl", is_flag=True, default=False,
              help="Explorar el sitio en busca de endpoints/parámetros reales "
                   "antes de escanear (links, forms, y rutas de API embebidas en "
                   "JS de SPAs). Necesario cuando la URL dada no tiene parámetros, "
                   "ej. la landing page de una app Angular/React/Vue.")
@click.option("--crawl-all", is_flag=True, default=False,
              help="Como --crawl, pero en vez de escanear solo el candidato de "
                   "mayor prioridad, corre un scan completo (recon + sqlmap + "
                   "IA + reporte) contra cada uno de los top --crawl-all-limit "
                   "candidatos encontrados, uno por uno, y al final muestra una "
                   "tabla consolidada + un JSON índice con el resultado de cada "
                   "endpoint. Implica --crawl.")
@click.option("--crawl-all-limit", default=10, type=click.IntRange(1, 100),
              help="Cuántos candidatos del crawler escanear con --crawl-all "
                   "(ordenados por prioridad, default: 10)")
@click.option("--resume", is_flag=True, default=False,
              help="Reusar el recon guardado de un scan anterior al mismo target "
                   "(evita repetir peticiones de WAF/Stack/ORM/GraphQL)")
@click.option("--ai-assist", is_flag=True, default=False,
              help="Si sqlmap no encuentra nada (o falla de forma ambigua), "
                   "pedir una segunda opinión con IA (Gemini) para payloads "
                   "avanzados/creativos específicos del stack detectado. "
                   "Requiere GEMINI_API_KEY (ver README). Primero prueba "
                   "técnicas ya aprendidas de scans anteriores — sin costo "
                   "de API — antes de preguntarle a Gemini algo nuevo. "
                   "OJO: manda datos del target a la API de Google.")
@click.option("--ai-max-calls", default=None, type=click.IntRange(1, None),
              help="Tope de llamadas a la API de Gemini para TODA la corrida "
                   "(compartido entre todos los targets si se usa junto con "
                   "--crawl-all). Sin esto, --ai-assist no tiene límite propio "
                   "más allá de --crawl-all-limit — con muchos candidatos eso "
                   "puede significar muchas llamadas a la API sin haberlo "
                   "decidido explícitamente. Ignorado sin --ai-assist.")
@click.option("--targets-file", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Archivo con una URL por línea (líneas vacías o que "
                   "empiezan con # se ignoran) para escanear cada una por "
                   "separado, igual que --crawl-all pero con una lista fija "
                   "de targets en vez de candidatos descubiertos por el "
                   "crawler. No se puede combinar con -u/--crawl-all.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Output detallado")
@click.option("-q", "--quiet", is_flag=True, default=False, help="Solo resultados finales")
def scan(url, param, method, data, cookie, header, stealth, fast,
         waf, technique, tamper, threads, level, risk, output_dir,
         report_format, graphql, nosql, websocket, no_sqlmap, proxy, tor,
         crawl, crawl_all, crawl_all_limit, resume, ai_assist, ai_max_calls,
         targets_file, verbose, quiet):
    """Ejecuta un scan completo de SQL Injection."""
    common.show_banner()
    configure_logging(verbose=verbose, quiet=quiet)

    if targets_file and url:
        raise click.UsageError(
            "--targets-file no se puede combinar con -u/--url."
        )
    if targets_file and crawl_all:
        raise click.UsageError(
            "--targets-file no se puede combinar con --crawl-all "
            "(son dos formas distintas de escanear múltiples targets)."
        )
    if not targets_file and not url:
        raise click.UsageError("Hace falta -u/--url o --targets-file.")

    file_target_urls = []
    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as f:
            file_target_urls = [
                line.strip() for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
        if not file_target_urls:
            raise click.UsageError(
                f"--targets-file '{targets_file}' no tiene ninguna URL válida "
                f"(una por línea, '#' para comentarios)."
            )

    # Configurar directorio de output
    output_dir = output_dir or os.environ.get(
        "INYECTOR_REPORTS_DIR", "/app/reports"
    )
    os.makedirs(output_dir, exist_ok=True)

    # Determinar modo stealth
    stealth_mode = True  # Default
    if fast:
        stealth_mode = False
    if stealth:
        stealth_mode = True

    # Proxy Tor
    if tor:
        proxy = proxy or "socks5://127.0.0.1:9050"

    common.console.print("[bold #00ff88][*] Iniciando reconocimiento...[/bold #00ff88]\n")

    # Crear sesión HTTP
    session = common.create_session(cookie=cookie, headers=list(header), proxy=proxy)

    if targets_file:
        targets = [(t_url, method, data, param) for t_url in file_target_urls]
        common.console.print(
            f"[bold #00ff88][*] --targets-file: escaneando "
            f"{len(targets)} target(s) desde '{targets_file}'...[/bold #00ff88]\n"
        )
    else:
        crawl_candidates = []
        if crawl or crawl_all:
            common.console.print(
                "[bold #00ff88][*] Explorando el sitio en busca de "
                "endpoints...[/bold #00ff88]"
            )
            crawl_candidates = Crawler().crawl(url, session)

            if crawl_candidates:
                common.console.print(
                    f"  [#00ff88]→[/] {len(crawl_candidates)} endpoint(s) "
                    f"candidato(s) encontrado(s):"
                )
                for c in crawl_candidates[:8]:
                    payload = c.get("params") or c.get("json_body") or {}
                    common.console.print(
                        f"    [dim]•[/] {c['method']} {c['url']} "
                        f"{list(payload.keys())} (prioridad: {c['priority']:.0%})"
                    )
            else:
                common.console.print(
                    "  [yellow]→ No se encontraron endpoints candidatos "
                    "adicionales[/yellow]"
                )
            common.console.print()

        # Si la URL original no tiene parámetros propios, hace falta un
        # candidato del crawler para tener algo que probar (el caso
        # exacto que motivó este módulo: la landing page de una SPA).
        original_has_params = "?" in url or bool(data)

        if crawl_all and crawl_candidates:
            chosen = crawl_candidates[:crawl_all_limit]
            targets = [_candidate_to_target(c, param) for c in chosen]
            common.console.print(
                f"[bold #00ff88][*] --crawl-all: escaneando los "
                f"{len(targets)} candidato(s) de mayor prioridad de "
                f"{len(crawl_candidates)} encontrados...[/bold #00ff88]\n"
            )
        elif crawl and crawl_candidates and not original_has_params:
            best_target = _candidate_to_target(crawl_candidates[0], param)
            targets = [best_target]
            common.console.print(
                f"  [bold #00ff88]→[/] Sin parámetros en la URL original — "
                f"usando el candidato de mayor prioridad en su lugar:\n"
                f"    [bold]{best_target[1]} {best_target[0]}[/bold]\n"
            )
        else:
            targets = [(url, method, data, param)]

    # Presupuesto de llamadas a Gemini compartido entre TODOS los
    # targets de esta corrida (--crawl-all/--targets-file incluidos) —
    # una sola instancia, no una por target.
    ai_budget = AICallBudget(ai_max_calls) if ai_assist else None

    opts = dict(
        waf=waf, technique=technique, tamper=tamper, threads=threads,
        level=level, risk=risk, output_dir=output_dir,
        report_format=report_format, graphql=graphql, nosql=nosql,
        no_sqlmap=no_sqlmap, proxy=proxy, stealth_mode=stealth_mode,
        resume=resume, ai_assist=ai_assist, ai_budget=ai_budget, verbose=verbose,
    )

    multi = len(targets) > 1
    results = []
    for i, (t_url, t_method, t_data, t_param) in enumerate(targets, start=1):
        if multi:
            common.console.print(
                f"\n[bold #00ff88]══════ Target {i}/{len(targets)}: "
                f"{t_method} {t_url} ══════[/bold #00ff88]\n"
            )
        results.append(_run_target_scan(
            t_url, t_param, t_method, t_data, cookie, header, session,
            opts, common.console,
        ))

    if multi:
        _show_crawl_all_summary(results, output_dir, common.console)


def _candidate_to_target(candidate: dict, cli_param):
    """Convierte un candidato del crawler en (url, method, data, param)
    listo para pasarle a _run_target_scan.

    Args:
        candidate: Un dict de Crawler().crawl() -- 'url', 'method', y
            'params' o 'json_body'.
        cli_param: El -p explícito del usuario, si lo hay -- tiene
            prioridad sobre el parámetro que detectó el crawler.

    Returns:
        Tupla (url, method, data, param).
    """
    c_url = candidate["url"]
    c_method = candidate["method"]
    c_data = None
    c_param = cli_param

    if candidate.get("json_body"):
        c_data = json.dumps(candidate["json_body"])
        c_param = c_param or next(iter(candidate["json_body"]), None)
    elif candidate.get("params"):
        if c_method == "POST":
            c_data = "&".join(
                f"{k}={v}" for k, v in candidate["params"].items()
            )
        else:
            c_url = f"{c_url}?" + "&".join(
                f"{k}={v}" for k, v in candidate["params"].items()
            )
        c_param = c_param or next(iter(candidate["params"]), None)

    return (c_url, c_method, c_data, c_param)


def _run_target_scan(url, param, method, data, cookie, header, session,
                      opts: dict, console) -> dict:
    """Corre el flujo completo (recon → inteligencia → ejecución → IA →
    reporte) contra UN target puntual.

    Extraída de scan() para poder correrla en loop una vez por
    candidato con --crawl-all, además del caso normal de un solo
    target. `opts` trae las opciones que NO varían entre targets de un
    mismo invocation (nivel, risk, WAF forzado, etc.) -- solo
    url/param/method/data cambian por iteración.

    Returns:
        Dict con url, method, param, vulnerable, severity,
        severity_score, scan_failed y reports (paths generados) --
        usado para armar la tabla consolidada de --crawl-all.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    stealth_engine = StealthEngine()

    # ════════════════════════════════════════════
    # FASE 1: RECONOCIMIENTO
    # ════════════════════════════════════════════
    session_store = SessionStore()
    recon_data = None
    if opts["resume"]:
        recon_data = session_store.load(opts["output_dir"], url, param, method)
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
            url, param, method, data, opts["waf"], session,
            opts["stealth_mode"], stealth_engine, opts["graphql"],
            opts["nosql"], console,
        )
        session_store.save(opts["output_dir"], url, param, method, recon_data)

    console.print()

    # Si es solo reconocimiento, terminar aquí
    if opts["no_sqlmap"]:
        console.print(
            "[yellow]⚠️  Modo --no-sqlmap: solo reconocimiento[/yellow]\n"
        )
        common._show_summary_table(url, recon_data, None, timestamp)
        report_paths = common._generate_reports(
            recon_data, {}, opts["output_dir"], timestamp,
            opts["report_format"],
        )
        return {
            "url": url, "method": method, "param": param,
            "vulnerable": None, "severity": None, "severity_score": None,
            "scan_failed": False, "reports": report_paths,
        }

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
    if opts["tamper"]:
        user_tampers = [t.strip() for t in opts["tamper"].split(",")]
        for t in user_tampers:
            if t not in selected_tampers:
                selected_tampers.append(t)

    recon_data["tampers_used"] = selected_tampers
    console.print(
        f"  [#00ff88]→[/] Tampers seleccionados: "
        f"[bold]{', '.join(selected_tampers) if selected_tampers else 'ninguno'}[/bold]"
    )

    # 2.2 Calcular timing
    timing_calc = TimingCalculator(stealth_mode=opts["stealth_mode"])
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
        "technique": opts["technique"],
        "level": opts["level"],
        "risk": opts["risk"],
        "threads": opts["threads"],
        "proxy": opts["proxy"],
        "output_dir": opts["output_dir"],
        "stealth": opts["stealth_mode"],
    }

    builder = CommandBuilder()
    sqlmap_command = builder.build(scan_config)

    if opts["verbose"]:
        console.print(f"\n  [dim]Comando: {sqlmap_command}[/dim]")

    console.print()

    # ════════════════════════════════════════════
    # FASE 3: EJECUCIÓN
    # ════════════════════════════════════════════
    console.print(
        "[bold #00ff88][*] Ejecutando sqlmap con configuración "
        "optimizada...[/bold #00ff88]\n"
    )

    execution_result, elapsed_time, auto_escalated = _execute_with_escalation(
        scan_config, sqlmap_command, opts, console,
    )

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
    parsed_results = parser.parse(execution_result["stdout"], opts["output_dir"], target_url=url)

    # Enriquecer resultados
    enricher = ResultEnricher()
    enriched = enricher.enrich(parsed_results, recon_data)
    enriched["auto_escalated"] = auto_escalated

    # La fase de IA es una "segunda opinión" — solo tiene sentido
    # cuando sqlmap NO confirmó nada (o terminó de forma ambigua). Si
    # ya encontró la vulnerabilidad, preguntarle a Gemini sería gastar
    # tokens sin necesidad.
    if opts["ai_assist"] and (not enriched.get("vulnerable") or scan_failed):
        _run_ai_assist_phase(
            url, session, param, recon_data, enriched,
            execution_result, scan_failed, opts["output_dir"], console,
            method=method, data=data, ai_budget=opts.get("ai_budget"),
        )

    # Generar reportes
    report_paths = common._generate_reports(
        recon_data, enriched, opts["output_dir"], timestamp,
        opts["report_format"],
    )

    for path in report_paths:
        ext = os.path.splitext(path)[1].upper().lstrip(".")
        console.print(f"  [green]✅ {ext}: {path}[/green]")

    console.print()

    # Mostrar resumen
    common._show_summary_table(
        url, recon_data, enriched, timestamp, elapsed_time, scan_failed,
    )

    return {
        "url": url, "method": method, "param": param,
        "vulnerable": enriched.get("vulnerable"),
        "severity": enriched.get("severity"),
        "severity_score": enriched.get("severity_score"),
        "scan_failed": scan_failed,
        "auto_escalated": auto_escalated,
        "reports": report_paths,
    }


def _execute_with_escalation(scan_config: dict, sqlmap_command: str,
                              opts: dict, console) -> tuple:
    """Corre sqlmap y, si concluye 'no vulnerable' sin haber probado
    de verdad el parámetro, reintenta UNA vez con --level/--risk al
    máximo antes de aceptar el resultado.

    Automatiza lo que tuvimos que hacer a mano varias veces contra UT
    Tehuacán: un scan con la config default terminaba en segundos
    porque sqlmap saltaba el parámetro por sospecha de intval()
    casting, y solo al reintentar manualmente con --level 5 --risk 3
    corría una batería de pruebas real.

    Args:
        scan_config: El dict que ya se le pasó a CommandBuilder para
            armar `sqlmap_command` -- se reusa (con level/risk
            escalados) si hace falta reintentar.
        sqlmap_command: Comando ya armado para el primer intento.
        opts: Opciones compartidas del target (incluye 'verbose',
            'output_dir').
        console: Consola Rich para imprimir el aviso de reintento.

    Returns:
        Tupla (execution_result, elapsed_time_total, escalated: bool).
    """
    start_time = time.time()
    runner = SqlmapRunner(verbose=opts["verbose"])
    execution_result = runner.run(sqlmap_command, opts["output_dir"])
    elapsed_time = time.time() - start_time

    already_max = (
        scan_config["level"] >= common.AUTO_ESCALATE_LEVEL
        and scan_config["risk"] >= common.AUTO_ESCALATE_RISK
    )
    shallow_reason = SqlmapRunner._detect_shallow_scan_reason(
        execution_result.get("stdout", ""),
    )

    if execution_result.get("vulnerabilities_found") or already_max or not shallow_reason:
        return execution_result, elapsed_time, False

    console.print(
        f"\n  [yellow]⚠️  sqlmap concluyó 'no vulnerable' sin probar "
        f"técnicas reales ('{shallow_reason}') — reintentando "
        f"automáticamente con --level={common.AUTO_ESCALATE_LEVEL} "
        f"--risk={common.AUTO_ESCALATE_RISK} antes de aceptarlo...[/yellow]\n"
    )

    escalated_config = {
        **scan_config,
        "level": common.AUTO_ESCALATE_LEVEL,
        "risk": common.AUTO_ESCALATE_RISK,
    }
    escalated_command = CommandBuilder().build(escalated_config)
    if opts["verbose"]:
        console.print(f"\n  [dim]Comando (escalado): {escalated_command}[/dim]")

    start_time2 = time.time()
    execution_result2 = runner.run(escalated_command, opts["output_dir"])
    elapsed_time2 = time.time() - start_time2

    return execution_result2, elapsed_time + elapsed_time2, True


def _show_crawl_all_summary(results: list, output_dir: str, console) -> None:
    """Tabla consolidada + JSON índice con el resultado de cada target
    escaneado en un --crawl-all."""
    table = Table(
        title="RESUMEN --crawl-all",
        title_style="bold #00ff88",
        border_style="#00ff88",
    )
    table.add_column("Target", overflow="fold")
    table.add_column("Método")
    table.add_column("Vulnerable")
    table.add_column("Severidad")

    for r in results:
        if r.get("scan_failed"):
            vuln_text = "[bold red]⚠️ DESCONOCIDO[/bold red]"
        elif r.get("vulnerable"):
            vuln_text = "[bold green]✅ SÍ[/bold green]"
        elif r.get("vulnerable") is None:
            vuln_text = "[dim]—[/dim]"
        else:
            vuln_text = "[yellow]❌ NO[/yellow]"
        table.add_row(
            r["url"], r["method"], vuln_text, str(r.get("severity") or "-"),
        )

    console.print()
    console.print(table)
    console.print()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = os.path.join(output_dir, f"crawl_all_summary_{timestamp}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    console.print(f"  [green]✅ Resumen consolidado: {summary_path}[/green]\n")


def _run_ai_assist_phase(
    url, session, param, recon_data, enriched,
    execution_result, scan_failed, output_dir, console,
    method="GET", data=None, ai_budget: Optional[AICallBudget] = None,
):
    """Segunda opinión con IA cuando sqlmap no encontró nada o falló
    de forma ambigua — con KnowledgeBase-first para no gastar tokens
    en algo que ya sabemos que funciona contra un stack parecido.

    Muta `enriched` in-place: agrega 'ai_assist' (historial completo
    de la fase, incluyendo sugerencias rechazadas — no solo lo
    confirmado, para que quede auditable en el reporte) y, si confirma
    algo nuevo, agrega a 'vulnerabilities' y sube 'severity'/'severity_score'.
    """
    console.print(
        "[bold #00ff88][*] Fase de asistencia con IA...[/bold #00ff88]"
    )

    stack = recon_data.get("stack", {})
    orm = recon_data.get("orm", {})
    waf = recon_data.get("waf", {})
    dbms = enriched.get("dbms", {})
    fingerprint = KnowledgeBase.fingerprint(stack, orm, waf, dbms)
    kb = KnowledgeBase(output_dir)
    audit_log = AIAuditLog(output_dir)

    # Historial completo de la fase (confirmado o no) — se adjunta a
    # `enriched` para que quede en los reportes, no solo en consola.
    ai_assist_report: dict[str, Any] = {
        "used": True,
        "fingerprint": fingerprint,
        "known_techniques_tried": [],
        "sqlmap_recovery": None,
        "gemini_suggestions": [],
        "audit_log_path": os.path.join(
            ".inyector_knowledge", "ai_decisions.jsonl",
        ),
    }
    enriched["ai_assist"] = ai_assist_report

    effective_param = param
    if not effective_param:
        injectable = recon_data.get("endpoints", {}).get("injectable_params", [])
        effective_param = injectable[0]["name"] if injectable else None

    if not effective_param:
        console.print(
            "  [yellow]→ No hay un parámetro claro para probar — se "
            "omite la asistencia de IA[/yellow]\n"
        )
        ai_assist_report["skipped_reason"] = "sin_parametro"
        return

    already_tried = []
    confirmed_findings = []

    # 1. Conocimiento previo primero — gratis, sin llamar a Gemini.
    known = kb.get_known_techniques(fingerprint)
    if known:
        console.print(
            f"  [#00ff88]→[/] {len(known)} técnica(s) conocida(s) para "
            f"este fingerprint ({fingerprint}) — probando antes de "
            f"gastar tokens..."
        )
        for t in known:
            already_tried.append(t["payload"])
            result = verify_payload(
                url, session, effective_param, t["payload"],
                method=method, data=data,
            )
            entry = {
                "source": "knowledge_base",
                "payload": t["payload"],
                "technique": t.get("technique", "custom"),
                "injection_point": t.get("injection_point", effective_param),
                "reasoning": t.get("reasoning", ""),
                "confirmed": result["confirmed"],
                "signal": result["signal"],
            }
            ai_assist_report["known_techniques_tried"].append(entry)
            if result["confirmed"]:
                console.print(
                    f"  [bold red]→ Confirmado con conocimiento previo:[/bold red] "
                    f"{t['payload']} ({result['signal']})"
                )
                kb.record_success(
                    fingerprint, t["payload"], t.get("technique", "custom"),
                    effective_param, t.get("reasoning", ""),
                )
                confirmed_findings.append({**t, **result})
            else:
                console.print(
                    f"  [dim]→ Técnica conocida no confirmada contra este "
                    f"target: {t['payload']} [{entry['technique']}][/dim]"
                )

    # 2. Si nada conocido funcionó, recién ahí preguntarle a Gemini.
    if not confirmed_findings:
        try:
            from inyector.intelligence.ai_assistant import AIAssistant
            assistant = AIAssistant(audit_log=audit_log, budget=ai_budget)
        except ValueError as e:
            if known:
                console.print(f"  [dim]→ {e}[/dim]\n")
            else:
                console.print(
                    f"  [yellow]→ {e}[/yellow]\n"
                )
            assistant = None

        if assistant and ai_budget is not None and ai_budget.exhausted:
            console.print(
                f"  [yellow]→ Tope de llamadas a Gemini alcanzado "
                f"(--ai-max-calls={ai_budget.max_calls}) — se omite para "
                f"este target[/yellow]\n"
            )
            ai_assist_report["skipped_reason"] = "ai_max_calls_exhausted"
            assistant = None

        if assistant:
            sample_response = ""
            try:
                sample_response = session.get(url, timeout=20).text
            except requests.exceptions.RequestException:
                pass

            if scan_failed:
                failure_reason = execution_result.get("failure_reason", "")
                recovery = assistant.suggest_sqlmap_recovery(
                    failure_reason, execution_result.get("stdout", ""),
                    {"technique": None, "level": None, "risk": None},
                )
                ai_assist_report["sqlmap_recovery"] = recovery
                if recovery.get("suggested_flags"):
                    console.print(
                        f"  [bold #00ff88]→[/] Gemini sugiere reintentar "
                        f"sqlmap con: {' '.join(recovery['suggested_flags'])}\n"
                        f"    [dim]{recovery.get('reasoning', '')}[/dim]"
                    )
                elif recovery.get("reasoning"):
                    console.print(
                        f"  [dim]→ Gemini no sugirió flags de recovery: "
                        f"{recovery['reasoning']}[/dim]"
                    )

            console.print("  [#00ff88]→[/] Pidiendo payloads avanzados a Gemini...")
            suggestions = assistant.suggest_advanced_payloads(
                stack, orm, waf, effective_param, sample_response, already_tried,
            )
            for s in suggestions:
                result = verify_payload(
                    url, session, effective_param, s["payload"],
                    method=method, data=data,
                )
                entry = {
                    "source": "gemini",
                    "payload": s["payload"],
                    "technique": s.get("technique", "custom"),
                    "injection_point": s.get("injection_point", effective_param),
                    "reasoning": s.get("reasoning", ""),
                    "confirmed": result["confirmed"],
                    "signal": result["signal"],
                }
                ai_assist_report["gemini_suggestions"].append(entry)
                if result["confirmed"]:
                    console.print(
                        f"  [bold red]→ CONFIRMADO por IA + verificación real:[/bold red] "
                        f"{s['payload']} ({result['signal']})"
                    )
                    kb.record_success(
                        fingerprint, s["payload"], s.get("technique", "custom"),
                        s.get("injection_point", effective_param),
                        s.get("reasoning", ""),
                    )
                    confirmed_findings.append({**s, **result})
                else:
                    console.print(
                        f"  [dim]→ Descartado (no confirmado): {s['payload']} "
                        f"[{entry['technique']} / {entry['injection_point']}]\n"
                        f"      motivo de Gemini: {entry['reasoning']}[/dim]"
                    )

            audit_log.record(
                kind="verification_round",
                fingerprint=fingerprint,
                param=effective_param,
                known_techniques_tried=ai_assist_report["known_techniques_tried"],
                gemini_suggestions=ai_assist_report["gemini_suggestions"],
            )

    if confirmed_findings:
        for f in confirmed_findings:
            enriched.setdefault("vulnerabilities", []).append({
                "parameter": f"{effective_param} (IA + verificación real)",
                "type": f.get("signal", "custom"),
                "title": f"Sugerido por asistencia de IA — {f.get('reasoning', '')}",
                "payload": f["payload"],
                "dbms": "", "dbms_version": "", "os": "",
                "technique": f.get("technique", "custom"),
                "severity": "CRÍTICO",
                "severity_score": 9.0,
            })
        enriched["vulnerable"] = True
        if enriched.get("severity_score", 0.0) < 9.0:
            enriched["severity"] = "CRÍTICO"
            enriched["severity_score"] = 9.0
        console.print(
            f"  [bold red]{len(confirmed_findings)} hallazgo(s) nuevo(s) "
            f"confirmado(s) por la fase de IA[/bold red]\n"
        )
    else:
        console.print("  [dim]→ Nada nuevo confirmado por la fase de IA[/dim]\n")
