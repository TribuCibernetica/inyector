"""Tests para CommandBuilder.

Regresión del bug: --data se armaba con comillas dobles a mano
('--data="{data}"'), lo cual rompe cuando el body es JSON (que trae
sus propias comillas dobles) — el comando resultante queda mal
formado para el shell. Encontrado al agregar soporte de --crawl para
candidatos de login vía JSON body.
"""

import shlex

from inyector.intelligence.command_builder import CommandBuilder


def _base_config(**overrides):
    config = {
        "url": "http://example.com/login",
        "param": None,
        "method": "GET",
        "data": None,
        "cookie": None,
        "headers": [],
        "waf": {"waf": "none"},
        "stack": {},
        "orm": {"orm": "none"},
        "timing": {},
        "tampers": [],
        "technique": None,
        "level": 2,
        "risk": 1,
        "threads": 3,
        "proxy": None,
        "output_dir": "/app/reports",
        "stealth": True,
    }
    config.update(overrides)
    return config


def test_json_post_body_is_shell_safe():
    json_body = '{"email": "a@a.com", "password": "x\'y"}'
    config = _base_config(method="POST", data=json_body)

    command = CommandBuilder().build(config)

    # El comando completo debe poder tokenizarse sin errores de shell
    # (shlex.split lanza ValueError si las comillas quedan mal
    # balanceadas, que es exactamente lo que pasaba con el bug viejo).
    tokens = shlex.split(command)
    data_flag = next(t for t in tokens if t.startswith("--data="))
    assert data_flag == f"--data={json_body}"


def test_cookie_with_special_characters_is_shell_safe():
    cookie = 'session=abc; other="quoted value"'
    config = _base_config(cookie=cookie)

    command = CommandBuilder().build(config)
    tokens = shlex.split(command)
    cookie_flag = next(t for t in tokens if t.startswith("--cookie="))
    assert cookie_flag == f"--cookie={cookie}"


def test_url_is_included_and_shell_safe():
    config = _base_config(url="http://example.com/search?q=hello world")
    command = CommandBuilder().build(config)
    tokens = shlex.split(command)
    assert "-u" in tokens
    assert tokens[tokens.index("-u") + 1] == "http://example.com/search?q=hello world"


def test_safe_freq_always_comes_with_a_safe_url():
    # Regresión real (UAEH): sqlmap ignora --safe-freq por completo si
    # no viene acompañado de --safe-url -- la pausa periódica pensada
    # para no verse como ráfaga de ataque nunca se activaba, aunque se
    # detectara WAF y se calculara un safe_freq > 0.
    config = _base_config(
        url="http://sistemas.uaeh.edu.mx/sape/index.php",
        timing={"delay": 2, "timeout": 30, "retries": 5, "safe_freq": 12},
    )

    command = CommandBuilder().build(config)
    tokens = shlex.split(command)

    assert "--safe-freq=12" in tokens
    safe_url_flag = next(t for t in tokens if t.startswith("--safe-url="))
    assert safe_url_flag == "--safe-url=http://sistemas.uaeh.edu.mx/"


def test_modsecurity_waf_does_not_add_hex_incompatible_with_no_cast():
    # Regresión real (UAEH): sqlmap rechaza la combinación de
    # '--no-cast' (siempre presente) con '--hex' ("switch '--no-cast'
    # is incompatible with switch '--hex'") -- el scan fallaba
    # instantáneamente (exit code 1, 0 requests mandadas) en cualquier
    # target detectado/forzado como modsecurity.
    config = _base_config(waf={"waf": "modsecurity"})

    command = CommandBuilder().build(config)
    tokens = shlex.split(command)

    assert "--no-cast" in tokens
    assert "--hex" not in tokens


def test_no_safe_url_added_when_safe_freq_is_zero():
    config = _base_config(
        timing={"delay": 1, "timeout": 30, "retries": 3, "safe_freq": 0},
    )

    command = CommandBuilder().build(config)

    assert "--safe-freq" not in command
    assert "--safe-url" not in command
