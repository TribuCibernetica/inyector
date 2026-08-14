"""Tests para DumpOutputParser.

Los fixtures acá son texto sintético siguiendo el formato documentado
de sqlmap (mismo estilo ASCII que ya usa `SqlmapOutputParser` para
'available databases'). Marcado explícitamente en el plan de esta
feature como best-effort hasta correr en vivo contra itescam.edu.mx y
ajustar contra el output real -- ver project_inyector_csrf_token_feature
y el plan de sesión para el contexto completo.
"""

from inyector.reporting.dump_parser import DumpOutputParser


def test_parses_current_db_user_hostname_is_dba():
    stdout = """
[INFO] fetching current database
current database:    'itescam_2011'
[INFO] fetching current user
current user:    'conex_full@%'
[INFO] fetching server hostname
hostname:    'itescam-db01'
[INFO] testing if current user is DBA
current user is DBA:    False
"""
    result = DumpOutputParser().parse(stdout)

    assert result["current_db"] == "itescam_2011"
    assert result["current_user"] == "conex_full@%"
    assert result["hostname"] == "itescam-db01"
    assert result["is_dba"] is False


def test_parses_databases_list():
    stdout = """
[INFO] fetching database names
available databases [3]:
[*] information_schema
[*] itescam_2011
[*] mysql

[*] ending @ 20:00:00
"""
    result = DumpOutputParser().parse(stdout)
    assert result["databases"] == ["information_schema", "itescam_2011", "mysql"]


def test_parses_tables_for_a_database():
    stdout = """
Database: itescam_2011
[3 tables]
+-----------+
| noticias  |
| secciones |
| usuarios  |
+-----------+
"""
    result = DumpOutputParser().parse(stdout)
    assert result["tables"]["itescam_2011"] == ["noticias", "secciones", "usuarios"]


def test_parses_columns_for_a_table():
    stdout = """
Database: itescam_2011
Table: usuarios
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(11)     |
| username | varchar(50) |
| password | varchar(255)|
+----------+-------------+
"""
    result = DumpOutputParser().parse(stdout)
    cols = result["columns"]["itescam_2011.usuarios"]
    assert {"name": "id", "type": "int(11)"} in cols
    assert {"name": "username", "type": "varchar(50)"} in cols
    assert len(cols) == 3


def test_dump_captures_row_count_and_column_names_never_values():
    # El punto central de este parser: nunca debe quedar un valor
    # extraído (credencial, hash, etc.) en la estructura que devuelve
    # -- decisión explícita del usuario, el reporte de inyector es
    # solo estructura y conteos.
    stdout = """
Database: itescam_2011
Table: usuarios
[2 entries]
+----+----------+---------------------+
| id | username | password            |
+----+----------+---------------------+
| 1  | admin    | 5f4dcc3b5aa765d61d8 |
| 2  | bob      | e10adc3949ba59abbe5 |
+----+----------+---------------------+
"""
    result = DumpOutputParser().parse(stdout)
    assert len(result["dumps"]) == 1
    dump = result["dumps"][0]
    assert dump["db"] == "itescam_2011"
    assert dump["table"] == "usuarios"
    assert dump["row_count"] == 2
    assert dump["columns"] == ["id", "username", "password"]

    # Ningún valor extraído debe filtrarse a ningún campo del resultado.
    import json
    serialized = json.dumps(result)
    assert "5f4dcc3b5aa765d61d8" not in serialized
    assert "admin" not in serialized or "admin" in dump["columns"]


def test_empty_stdout_returns_empty_structure():
    result = DumpOutputParser().parse("")
    assert result["current_db"] == ""
    assert result["databases"] == []
    assert result["tables"] == {}
    assert result["dumps"] == []
