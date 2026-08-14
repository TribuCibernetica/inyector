"""Parsing del output de sqlmap en modo enumeración/extracción
(`--current-db`, `--dbs`, `--tables`, `--columns`, `--dump`,
`--dump-all`, `--search`).

Separado de `SqlmapOutputParser` (que parsea el modo DETECCIÓN) a
propósito: el modo dump imprime marcadores completamente distintos
-- "testing for sql injection on ..." (que usa `SqlmapOutputParser`/
`SqlmapRunner` para reconocer que hubo una prueba real) nunca aparece
en una corrida de `dump` que resume una sesión ya confirmada, sqlmap
va directo a enumerar/extraer.

A propósito, esta clase NUNCA captura los valores extraídos por
--dump, solo nombres de columna y cantidad de filas -- los valores
reales quedan en el CSV/archivo que sqlmap ya genera por su cuenta
bajo `<output_dir>/<host>/dump/<db>/<tabla>.csv`. Decisión explícita
del usuario: el reporte de inyector muestra estructura y conteos, no
datos sensibles inline.
"""

import re
from typing import Any

from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class DumpOutputParser:
    """Parsea el output de sqlmap en modo enumeración/extracción."""

    def parse(self, stdout: str) -> dict:
        """Parsea el output completo de una corrida de `dump`.

        Args:
            stdout: Output de texto de sqlmap.

        Returns:
            Dict con current_db/current_user/hostname/is_dba,
            databases (lista), tables (dict db -> lista de tablas),
            columns (dict "db.tabla" -> lista de {"name", "type"}), y
            dumps (lista de {"db", "table", "columns": [...],
            "row_count": int} -- sin valores).
        """
        resultado: dict[str, Any] = {
            "current_db": "",
            "current_user": "",
            "hostname": "",
            "is_dba": None,
            "databases": [],
            "tables": {},
            "columns": {},
            "dumps": [],
        }

        current_db_match = re.search(r"current database:\s+'([^']*)'", stdout)
        if current_db_match:
            resultado["current_db"] = current_db_match.group(1)

        current_user_match = re.search(r"current user:\s+'([^']*)'", stdout)
        if current_user_match:
            resultado["current_user"] = current_user_match.group(1)

        hostname_match = re.search(r"hostname:\s+'([^']*)'", stdout)
        if hostname_match:
            resultado["hostname"] = hostname_match.group(1)

        is_dba_match = re.search(r"current user is DBA:\s+(True|False)", stdout)
        if is_dba_match:
            resultado["is_dba"] = is_dba_match.group(1) == "True"

        resultado["databases"] = self._parse_databases(stdout)
        resultado["tables"] = self._parse_tables(stdout)
        resultado["columns"] = self._parse_columns(stdout)
        resultado["dumps"] = self._parse_dumps(stdout)

        return resultado

    def _parse_databases(self, text: str) -> list[str]:
        """Extrae la lista de bases de datos de `--dbs`.

        sqlmap imprime "available databases [N]:" seguido de una línea
        "[*] nombre" por base.
        """
        blocks = re.findall(
            r"available databases\s*\[\d+\]:\n(.*?)(?=\n\n|\Z)",
            text, re.DOTALL,
        )
        databases: list[str] = []
        for block in blocks:
            databases.extend(re.findall(r"\[\*\]\s+(\S+)", block))
        return databases

    def _parse_tables(self, text: str) -> dict[str, list[str]]:
        """Extrae tablas por base de datos de `--tables`.

        Formato de sqlmap: "Database: db" seguido de "[N tables]" y
        una tabla ASCII con una columna (nombre de tabla).
        """
        tables: dict[str, list[str]] = {}
        blocks = re.findall(
            r"Database:\s+(\S+)\n\[\d+\s+tables?\]\n\+[-+]+\+\n(.*?)\n\+[-+]+\+",
            text, re.DOTALL,
        )
        for db, body in blocks:
            names = [row.strip() for row in re.findall(r"\|\s*(.+?)\s*\|", body)]
            tables[db] = names
        return tables

    def _parse_columns(self, text: str) -> dict[str, list[dict]]:
        """Extrae columnas (nombre + tipo) por 'db.tabla' de `--columns`.

        Formato: "Database: db\\nTable: tabla\\n[N columns]" seguido de
        una tabla ASCII con dos columnas (Column, Type).
        """
        columns: dict[str, list[dict]] = {}
        blocks = re.findall(
            r"Database:\s+(\S+)\nTable:\s+(\S+)\n\[\d+\s+columns?\]\n"
            r"\+[-+]+\+\n\|\s*Column\s*\|\s*Type\s*\|\n\+[-+]+\+\n(.*?)\n\+[-+]+\+",
            text, re.DOTALL,
        )
        for db, table, body in blocks:
            rows = re.findall(r"\|\s*(.+?)\s*\|\s*(.+?)\s*\|", body)
            columns[f"{db}.{table}"] = [
                {"name": name, "type": col_type} for name, col_type in rows
            ]
        return columns

    def _parse_dumps(self, text: str) -> list[dict]:
        """Extrae metadata de `--dump`/`--dump-all` SIN los valores.

        Formato: "Database: db\\nTable: tabla\\n[N entries]" seguido de
        una tabla ASCII -- se captura la fila de encabezado (nombres de
        columna) y el conteo de filas, nunca las filas de datos.
        """
        dumps = []
        blocks = re.findall(
            r"Database:\s+(\S+)\nTable:\s+(\S+)\n\[(\d+)\s+entr(?:y|ies)\]\n"
            r"\+[-+]+\+\n\|(.+?)\|\n\+[-+]+\+",
            text, re.DOTALL,
        )
        for db, table, row_count, header_row in blocks:
            column_names = [c.strip() for c in header_row.split("|")]
            dumps.append({
                "db": db,
                "table": table,
                "columns": column_names,
                "row_count": int(row_count),
            })
        return dumps
