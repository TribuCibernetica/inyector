"""Comando `recon` — solo reconocimiento, sin ejecutar sqlmap."""

import click

from inyector.commands import common
from inyector.utils.logger import configure_logging
from inyector.recon.waf_detector import WAFDetector
from inyector.recon.stack_detector import StackDetector
from inyector.recon.orm_detector import ORMDetector
from inyector.recon.graphql_detector import GraphQLDetector
from inyector.recon.nosqli_detector import NoSQLiDetector
from inyector.recon.endpoint_mapper import EndpointMapper
from inyector.intelligence.confidence_calibrator import ConfidenceCalibrator


@click.command(name="recon")
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
    common.show_banner()
    configure_logging(verbose=verbose)

    common.console.print(
        "[bold #00ff88][*] Modo reconocimiento (sin sqlmap)[/bold #00ff88]\n"
    )

    session = common.create_session(
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
    common.console.print("  [cyan]Detectando WAF...[/cyan]")
    waf_result = WAFDetector().detect(url, session)
    recon_data["waf"] = waf_result
    common.console.print(
        f"  [#00ff88]→[/] WAF: [bold]{waf_result['waf']}[/bold] "
        f"({waf_result['confidence']:.0%}){common._error_suffix(waf_result)}"
    )

    # Stack
    common.console.print("  [cyan]Detectando stack...[/cyan]")
    stack_result = StackDetector().detect(url, session, param=effective_param)
    recon_data["stack"] = stack_result
    common.console.print(
        f"  [#00ff88]→[/] Stack: [bold]{stack_result['framework']}[/bold]"
        f"{common._error_suffix(stack_result)}"
    )

    # ORM
    common.console.print("  [cyan]Detectando ORM...[/cyan]")
    orm_result = ORMDetector().detect(url, session, param=effective_param)
    recon_data["orm"] = orm_result
    common.console.print(
        f"  [#00ff88]→[/] ORM: [bold]{orm_result['orm']}[/bold]"
        f"{common._error_suffix(orm_result)}"
    )

    # GraphQL
    if graphql:
        common.console.print("  [cyan]Buscando endpoints GraphQL...[/cyan]")
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
        common.console.print(
            f"  [#00ff88]→[/] GraphQL: [bold]{len(endpoints)} endpoint(s)[/bold]"
        )
        if endpoints and graphql_data["engine"] != "unknown":
            common.console.print(
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
        common.console.print("  [cyan]Buscando NoSQL injection...[/cyan]")
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

        common.console.print(f"  [#00ff88]→[/] NoSQL: motor [bold]{engine_fp['engine']}[/bold]")
        if op_result["vulnerable"]:
            common.console.print(
                f"  [bold red]→ Operator injection confirmada[/bold red] "
                f"en '{task_param}'"
            )
        if where_result["vulnerable"]:
            common.console.print(
                f"  [bold red]→ $where injection confirmada[/bold red] "
                f"en '{task_param}'"
            )

    recon_data["nosqli"] = nosqli_data

    ConfidenceCalibrator().calibrate(recon_data)
    for note in recon_data.get("consistency_notes", []):
        common.console.print(f"  [dim]ℹ {note}[/dim]")

    common.console.print()
    common._show_summary_table(url, recon_data)
