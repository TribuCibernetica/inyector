"""Tests para el comando `dump`.

Cubre la resolución de acción por CLI (_resolve_dump_action) y la
escalera de reintentos "pentester persistente" (_run_dump_with_persistence)
-- mockeando SqlmapRunner igual que hace tests/test_targets_file.py con
_run_target_scan, sin correr sqlmap real.
"""

from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from inyector.cli import main
from inyector.commands.dump import _resolve_dump_action, _run_dump_with_persistence


def test_no_action_flag_is_a_usage_error():
    with pytest.raises(click.UsageError):
        _resolve_dump_action(
            current=False, dbs=False, db=None, tables=False, table=None,
            columns=False, do_dump=False, columns_list=None, where=None,
            start=None, stop=None, do_dump_all=False, include_sysdbs=False,
            search_term=None,
        )


def test_current_action_is_cheap():
    action, cheap = _resolve_dump_action(
        current=True, dbs=False, db=None, tables=False, table=None,
        columns=False, do_dump=False, columns_list=None, where=None,
        start=None, stop=None, do_dump_all=False, include_sysdbs=False,
        search_term=None,
    )
    assert action == {"action": "current"}
    assert cheap is True


def test_dump_action_requires_db_and_table():
    with pytest.raises(click.UsageError):
        _resolve_dump_action(
            current=False, dbs=False, db=None, tables=False, table=None,
            columns=False, do_dump=True, columns_list=None, where=None,
            start=None, stop=None, do_dump_all=False, include_sysdbs=False,
            search_term=None,
        )


def test_dump_action_is_not_cheap():
    # Grounded en itescam.edu.mx: database() = 'itescam_2011'.
    action, cheap = _resolve_dump_action(
        current=False, dbs=False, db="itescam_2011", tables=False,
        table="usuarios", columns=False, do_dump=True, columns_list=None,
        where=None, start=None, stop=None, do_dump_all=False,
        include_sysdbs=False, search_term=None,
    )
    assert action["action"] == "dump"
    assert action["db"] == "itescam_2011"
    assert action["table"] == "usuarios"
    assert cheap is False


def test_dump_all_defaults_to_excluding_sysdbs():
    action, cheap = _resolve_dump_action(
        current=False, dbs=False, db=None, tables=False, table=None,
        columns=False, do_dump=False, columns_list=None, where=None,
        start=None, stop=None, do_dump_all=True, include_sysdbs=False,
        search_term=None,
    )
    assert action == {"action": "dump_all", "exclude_sysdbs": True}
    assert cheap is False


def test_cli_requires_at_least_one_action(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main, ["dump", "-u", "http://x.com/page.php?id=1", "-p", "id"],
    )
    assert result.exit_code != 0
    assert "al menos una acción" in result.output.lower()


def _fake_sqlmap_run(stdout: str, connection_issue: bool = False):
    return {
        "success": not connection_issue, "exit_code": 0 if not connection_issue else 1,
        "stdout": stdout, "stderr": "", "vulnerabilities_found": False,
        "connection_issue": connection_issue, "failure_reason": "",
    }


def test_persistence_ladder_stops_at_first_non_empty_result():
    # El primer intento ya trae datos -- no debe escalar ni forzar
    # técnicas.
    scan_config = {"url": "http://x.com", "param": "id", "technique": None}

    with patch("inyector.commands.dump.SqlmapRunner") as MockRunner:
        instance = MockRunner.return_value
        instance.run.return_value = _fake_sqlmap_run(
            "current database:    'itescam_2011'",
        )
        parsed, attempts = _run_dump_with_persistence(
            scan_config, "/tmp/reports", False, True, MagicMock(),
        )

    assert parsed["current_db"] == "itescam_2011"
    assert len(attempts) == 1
    assert instance.run.call_count == 1


def test_persistence_ladder_escalates_level_risk_when_empty():
    scan_config = {"url": "http://x.com", "param": "id", "technique": None}

    with patch("inyector.commands.dump.SqlmapRunner") as MockRunner:
        instance = MockRunner.return_value
        instance.run.side_effect = [
            _fake_sqlmap_run(""),  # intento 1: vacío
            _fake_sqlmap_run("current database:    'itescam_2011'"),  # escalado: datos
        ]
        parsed, attempts = _run_dump_with_persistence(
            scan_config, "/tmp/reports", False, True, MagicMock(),
        )

    assert parsed["current_db"] == "itescam_2011"
    assert len(attempts) == 2
    assert attempts[0]["empty"] is True
    assert attempts[1]["empty"] is False


def test_persistence_ladder_forces_techniques_for_cheap_actions():
    scan_config = {"url": "http://x.com", "param": "id", "technique": None}

    with patch("inyector.commands.dump.SqlmapRunner") as MockRunner:
        instance = MockRunner.return_value
        instance.run.side_effect = [
            _fake_sqlmap_run(""),  # config inicial: vacío
            _fake_sqlmap_run(""),  # escalado: vacío
            _fake_sqlmap_run(""),  # técnica E: vacío
            _fake_sqlmap_run("available databases [1]:\n[*] itescam_2011\n\n"),  # técnica U: datos
        ]
        parsed, attempts = _run_dump_with_persistence(
            scan_config, "/tmp/reports", False, True, MagicMock(),
        )

    assert parsed["databases"] == ["itescam_2011"]
    assert len(attempts) == 4
    assert attempts[-1]["label"] == "técnica forzada U"


def test_persistence_ladder_does_not_force_techniques_for_expensive_dump():
    # --dump/--dump-all sobre una tabla completa: solo se escala
    # level/risk UNA vez, nunca se prueban las 5 técnicas (podría
    # tardar horas con boolean-blind).
    scan_config = {"url": "http://x.com", "param": "id", "technique": None}

    with patch("inyector.commands.dump.SqlmapRunner") as MockRunner:
        instance = MockRunner.return_value
        instance.run.side_effect = [
            _fake_sqlmap_run(""),  # config inicial: vacío
            _fake_sqlmap_run(""),  # escalado: vacío -- y se rinde acá
        ]
        parsed, attempts = _run_dump_with_persistence(
            scan_config, "/tmp/reports", False, False, MagicMock(),
        )

    assert len(attempts) == 2
    assert instance.run.call_count == 2


def test_persistence_ladder_stops_on_hard_connection_failure():
    # Un fallo de conexión real no debe reintentar con escalada --
    # reintentar contra un target caído no va a dar resultados
    # distintos.
    scan_config = {"url": "http://x.com", "param": "id", "technique": None}

    with patch("inyector.commands.dump.SqlmapRunner") as MockRunner:
        instance = MockRunner.return_value
        instance.run.return_value = _fake_sqlmap_run("", connection_issue=True)
        parsed, attempts = _run_dump_with_persistence(
            scan_config, "/tmp/reports", False, True, MagicMock(),
        )

    assert len(attempts) == 1
    assert attempts[0]["hard_failure"] is True


def test_persistence_ladder_does_not_force_technique_if_user_already_forced_one():
    scan_config = {"url": "http://x.com", "param": "id", "technique": "B"}

    with patch("inyector.commands.dump.SqlmapRunner") as MockRunner:
        instance = MockRunner.return_value
        instance.run.side_effect = [
            _fake_sqlmap_run(""),  # config inicial (técnica B forzada por usuario): vacío
            _fake_sqlmap_run(""),  # escalado: vacío -- no debe seguir forzando otras técnicas
        ]
        parsed, attempts = _run_dump_with_persistence(
            scan_config, "/tmp/reports", False, True, MagicMock(),
        )

    assert len(attempts) == 2
    assert instance.run.call_count == 2
