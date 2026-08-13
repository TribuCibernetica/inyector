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


def test_aspnet_webforms_param_name_is_shell_safe():
    # Regresión real (cloud.teziutlan.tecnm.mx): nombres de campo de
    # ASP.NET WebForms como 'ctl00$cphContenido$txtNoControl' traen '$'
    # literales. Sin shlex.quote, shell=True (en sqlmap_runner.py)
    # expandía '$cphContenido' y '$txtNoControl' como variables de
    # entorno vacías, truncando el param a 'ctl00' -- sqlmap no
    # encontraba ese nombre en el POST real y terminaba en segundos
    # con 'no vulnerable' sin haber probado nada.
    param = "ctl00$cphContenido$txtNoControl"
    config = _base_config(param=param)

    command = CommandBuilder().build(config)
    tokens = shlex.split(command)

    assert "-p" in tokens
    assert tokens[tokens.index("-p") + 1] == param


def test_csrf_token_and_url_are_appended_when_present():
    # Grounded en tie.teziutlan.tecnm.mx: el 'logintoken' de Moodle es
    # de un solo uso -- sqlmap necesita --csrf-token/--csrf-url para
    # refrescarlo antes de cada request en vez de mandar siempre el
    # mismo valor capturado (que ya viene en --data como fallback para
    # el primer request).
    config = _base_config(
        method="POST",
        data="anchor=&logintoken=PLACEHOLDER&username=test&password=test",
        param="username",
        csrf_token="logintoken",
        csrf_url="https://tie.teziutlan.tecnm.mx/m24/login/index.php",
    )

    command = CommandBuilder().build(config)
    tokens = shlex.split(command)

    assert "--csrf-token=logintoken" in tokens
    assert (
        "--csrf-url=https://tie.teziutlan.tecnm.mx/m24/login/index.php"
        in tokens
    )
    assert "--csrf-method=GET" in tokens
    # El valor estático capturado se deja igual en --data -- sqlmap lo
    # necesita para armar el primer request antes de refrescarlo solo.
    assert any(t.startswith("--data=") and "logintoken=PLACEHOLDER" in t
               for t in tokens)


def test_csrf_token_omits_threads_flag():
    # Regresión real (tie.teziutlan.tecnm.mx): sqlmap rechaza la
    # combinación '--csrf-token' + '--threads' ("option '--csrf-token'
    # is incompatible with option '--threads'") -- el scan fallaba
    # instantáneamente (exit code 1, 0 requests mandadas) en CUALQUIER
    # target con un token CSRF wireado, sin importar si era realmente
    # inyectable o no.
    config = _base_config(csrf_token="logintoken", threads=5)

    command = CommandBuilder().build(config)
    tokens = shlex.split(command)

    assert "--csrf-token=logintoken" in tokens
    assert not any(t.startswith("--threads=") for t in tokens)


def test_no_csrf_flags_when_csrf_token_absent():
    # No-regresión: la config default (sin csrf_token) -- la inmensa
    # mayoría de targets -- no debe cambiar de comportamiento.
    command = CommandBuilder().build(_base_config())

    assert "--csrf-token" not in command
    assert "--csrf-url" not in command
    assert "--csrf-method" not in command


def test_no_safe_url_added_when_safe_freq_is_zero():
    config = _base_config(
        timing={"delay": 1, "timeout": 30, "retries": 3, "safe_freq": 0},
    )

    command = CommandBuilder().build(config)

    assert "--safe-freq" not in command
    assert "--safe-url" not in command
