"""Módulo de ejecución de sqlmap.

Ejecuta sqlmap como subprocess, captura su output en tiempo real
y muestra el progreso al usuario con indicadores visuales.
"""

import subprocess
import threading
import os
from typing import Optional
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class SqlmapRunner:
    """Ejecuta sqlmap y captura su output en tiempo real."""

    # Mapeo de líneas de sqlmap a mensajes en español
    PROGRESS_MAP = {
        "testing connection": "Probando conexión al target...",
        "testing if the target url is stable": "Verificando estabilidad del target...",
        "testing if the target url content is stable": "Verificando estabilidad del contenido...",
        "heuristic (basic) test": "Test heurístico inicial...",
        "heuristic (xss) test": "Test heurístico XSS...",
        "testing for sql injection": "Probando SQL Injection...",
        "testing if the injection point": "Verificando punto de inyección...",
        "sqlmap identified": "¡Vulnerabilidad identificada!",
        "fetching": "Extrayendo información...",
        "the back-end dbms is": "DBMS identificado...",
        "testing if get parameter": "Probando parámetro GET...",
        "testing if post parameter": "Probando parámetro POST...",
        "it is recommended": "Ajustando configuración...",
        "resuming": "Reanudando sesión anterior...",
        "checking": "Verificando...",
    }

    # Marcadores que indican que sqlmap nunca llegó a probar SQLi
    # realmente (falla de conexión, target inestable, etc). sqlmap
    # suele salir con exit code 0 en estos casos, así que el exit
    # code por sí solo NO alcanza para distinguir "no vulnerable"
    # de "no se pudo ni conectar".
    CONNECTION_FAILURE_MARKERS = [
        "unable to connect to the target url",
        "unable to connect to the target",
        "target url content is not stable",
        "no parameter(s) found for testing",
        "connection timed out",
        "temporary failure in name resolution",
        "connection reset by peer",
    ]

    def __init__(self, verbose: bool = False):
        """Inicializa el runner de sqlmap.

        Args:
            verbose: Si es True, muestra todo el output de sqlmap.
        """
        self.verbose = verbose
        self.console = Console()

    def run(self, command: str, output_dir: str) -> dict:
        """Ejecuta sqlmap como subprocess.

        Args:
            command: Comando sqlmap completo.
            output_dir: Directorio de output para resultados.

        Returns:
            Diccionario con success, exit_code, stdout, stderr,
            vulnerabilities_found y command_used.
        """
        logger.info("Ejecutando sqlmap...")

        os.makedirs(output_dir, exist_ok=True)

        resultado = {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "vulnerabilities_found": False,
            "command_used": command,
        }

        if self.verbose:
            self.console.print(f"\n[dim]Comando: {command}[/dim]\n")

        stdout_lines = []
        stderr_lines = []
        current_status = "Iniciando sqlmap..."
        vuln_found = False

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )

            # Thread para capturar stderr
            def capture_stderr():
                for line in process.stderr:
                    stderr_lines.append(line.rstrip())

            stderr_thread = threading.Thread(target=capture_stderr, daemon=True)
            stderr_thread.start()

            if self.verbose:
                for line in process.stdout:
                    line = line.rstrip()
                    stdout_lines.append(line)

                    if "sqlmap identified the following injection point" in line.lower():
                        self.console.print(f"[bold green]{line}[/bold green]")
                        vuln_found = True
                    elif "[warning]" in line.lower():
                        self.console.print(f"[yellow]{line}[/yellow]")
                    elif "[error]" in line.lower() or "[critical]" in line.lower():
                        self.console.print(f"[red]{line}[/red]")
                    elif "[info]" in line.lower():
                        self.console.print(f"[dim]{line}[/dim]")
                    else:
                        self.console.print(line)
            else:
                with Live(
                    Spinner("dots", text=Text(current_status, style="cyan")),
                    console=self.console,
                    refresh_per_second=4,
                ) as live:
                    for line in process.stdout:
                        line = line.rstrip()
                        stdout_lines.append(line)

                        new_status = self._parse_progress(line)
                        if new_status:
                            current_status = new_status
                            if "identificada" in new_status:
                                vuln_found = True
                                live.update(
                                    Text(f"✅ {new_status}", style="bold green")
                                )
                            else:
                                live.update(
                                    Spinner(
                                        "dots",
                                        text=Text(current_status, style="cyan"),
                                    )
                                )

            process.wait()
            stderr_thread.join(timeout=5)

            stdout_text = "\n".join(stdout_lines)
            failure_reason = self._detect_failure_reason(stdout_text)

            resultado["success"] = process.returncode == 0 and failure_reason is None
            resultado["exit_code"] = process.returncode
            resultado["stdout"] = stdout_text
            resultado["stderr"] = "\n".join(stderr_lines)
            resultado["vulnerabilities_found"] = vuln_found
            resultado["connection_issue"] = failure_reason is not None
            resultado["failure_reason"] = failure_reason or ""

            if vuln_found:
                self.console.print(
                    "\n[bold green]✅ Vulnerabilidades detectadas por sqlmap[/bold green]"
                )
            elif failure_reason:
                self.console.print(
                    f"\n[bold red]⚠️  sqlmap no pudo completar la prueba real: "
                    f"'{failure_reason}'. El resultado NO es un 'no vulnerable' "
                    f"confiable.[/bold red]"
                )
            else:
                self.console.print(
                    "\n[yellow]⚠️  No se detectaron vulnerabilidades en este scan[/yellow]"
                )

        except FileNotFoundError:
            logger.error("sqlmap no encontrado en el PATH")
            resultado["stderr"] = "sqlmap no encontrado. Verifica la instalación."
        except subprocess.SubprocessError as e:
            logger.error(f"Error al ejecutar sqlmap: {e}")
            resultado["stderr"] = str(e)
        except Exception as e:
            logger.error(f"Error inesperado al ejecutar sqlmap: {e}")
            resultado["stderr"] = str(e)

        return resultado

    @classmethod
    def _detect_failure_reason(cls, stdout_text: str) -> Optional[str]:
        """Busca marcadores de fallo real en el output de sqlmap.

        Separado en un método propio (sin tocar el proceso) para
        poder testearlo con texto de ejemplo, sin correr sqlmap.

        Args:
            stdout_text: Output completo (stdout) de sqlmap.

        Returns:
            El marcador encontrado, o None si no hay indicios de fallo.
        """
        stdout_lower = stdout_text.lower()
        return next(
            (
                marker for marker in cls.CONNECTION_FAILURE_MARKERS
                if marker in stdout_lower
            ),
            None,
        )

    def _parse_progress(self, line: str) -> str:
        """Extrae el estado actual del output de sqlmap.

        Args:
            line: Línea de output de sqlmap.

        Returns:
            Mensaje de estado traducido o string vacío.
        """
        line_lower = line.lower()

        for pattern, message in self.PROGRESS_MAP.items():
            if pattern in line_lower:
                return message

        return ""
