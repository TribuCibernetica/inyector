"""Tests para --targets-file.

Cubre las validaciones de uso (mutuamente excluyente con -u y con
--crawl-all, archivo sin URLs válidas) vía CliRunner -- estas
validaciones corren ANTES de tocar red, así que no hace falta mockear
el pipeline completo. También cubre el parseo real de líneas
(comentarios '#' y líneas vacías se ignoran) mockeando el resto del
pipeline (create_session/_run_target_scan/_show_crawl_all_summary),
para verificar que cada URL del archivo efectivamente se corre como
un target independiente -- sin llegar a ejecutar sqlmap real.
"""

from unittest.mock import MagicMock

from click.testing import CliRunner

from inyector.cli import main


def test_targets_file_and_url_are_mutually_exclusive(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("http://a.com/?id=1\n")

    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "-u", "http://x.com", "--targets-file", str(targets)],
    )

    assert result.exit_code != 0
    assert "no se puede combinar" in result.output.lower()


def test_targets_file_and_crawl_all_are_mutually_exclusive(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("http://a.com/?id=1\n")

    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "--targets-file", str(targets), "--crawl-all"],
    )

    assert result.exit_code != 0
    assert "crawl-all" in result.output.lower()


def test_missing_both_url_and_targets_file_is_an_error():
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])

    assert result.exit_code != 0
    assert "targets-file" in result.output.lower()


def test_targets_file_with_only_comments_and_blanks_is_an_error(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("# solo comentarios\n\n   \n# nada real\n")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--targets-file", str(targets)])

    assert result.exit_code != 0
    assert "ninguna url" in result.output.lower()


def test_targets_file_parses_one_target_per_valid_line(tmp_path, monkeypatch):
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "http://a.com/?id=1\n"
        "# comentario, se ignora\n"
        "\n"
        "http://b.com/?id=2\n"
        "   \n"
    )

    seen_urls = []

    def fake_run_target_scan(url, param, method, data, cookie, header,
                              session, opts, console):
        seen_urls.append(url)
        return {"url": url, "method": method, "vulnerable": False, "severity": None}

    monkeypatch.setattr("inyector.commands.common.create_session", lambda **kw: MagicMock())
    monkeypatch.setattr("inyector.commands.scan._run_target_scan", fake_run_target_scan)
    monkeypatch.setattr("inyector.commands.scan._show_crawl_all_summary", lambda *a, **kw: None)

    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "--targets-file", str(targets), "--no-sqlmap"],
    )

    assert result.exit_code == 0, result.output
    assert seen_urls == ["http://a.com/?id=1", "http://b.com/?id=2"]
