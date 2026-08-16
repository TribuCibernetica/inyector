# Changelog

Todos los cambios notables de este proyecto se documentan acá.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto usa [Semantic Versioning](https://semver.org/lang/es/):
`MAJOR.MINOR.PATCH` — MAJOR para cambios incompatibles, MINOR para
funcionalidad nueva compatible hacia atrás, PATCH para fixes.

## [Unreleased]

## [1.1.0] - 2026-08-16

### Corregido
- `WAFBypassProber._safe_get` seguía redirects (`allow_redirects=True`)
  al probar cada mutación -- misma clase de bug que el fix de
  `--ignore-redirects` de abajo, pero en el prober nuevo en vez de en
  sqlmap: contra un WAF `keyword_sinkhole`, cada mutación que seguía
  bloqueada disparaba reintentos de resolución DNS de varios segundos
  contra el dominio sinkhole antes de darse por vencida, sin aportar
  nada (el header `Location` crudo ya alcanza para clasificar el
  bloqueo). Encontrado en la misma corrida en vivo contra
  `itescam.edu.mx` que reveló el bug de abajo. Ahora usa
  `allow_redirects=False` igual que el probe de sinkhole que ya existe
  en `WAFDetector`.
- `CommandBuilder.build` no agregaba `--ignore-redirects` contra WAFs
  `keyword_sinkhole` (los que bloquean redirigiendo a un dominio ajeno
  que ni resuelve). Sin ese flag, sqlmap sigue el redirect (default de
  `--batch`) y reintenta la resolución DNS varias veces con backoff
  antes de rendirse, metiendo demoras variables de varios segundos en
  cada request bloqueado — que contaminan justo la señal que mide la
  técnica time-based blind (un reintento de DNS es indistinguible de
  un `SLEEP` real). Bug real encontrado verificando en vivo el
  descubrimiento de bypass de WAF contra `itescam.edu.mx`: sqlmap
  marcaba `id` como injectable en el heurístico inicial, pero su
  propia re-verificación lo rechazaba después, aun con los tampers
  correctos (`space2comment`, `scalarfuncbypass`) ya seleccionados —
  el problema nunca fue de tampers, era el ruido del redirect
  perturbando la medición de tiempo.
- `CommandBuilder.build` siempre agregaba `--threads`, aunque sqlmap
  rechaza la combinación `--csrf-token` + `--threads` ("option
  '--csrf-token' is incompatible with option '--threads'") — el scan
  fallaba instantáneamente (exit code 1, 0 requests mandadas) en
  cualquier target con un token CSRF wireado. Bug real encontrado
  verificando en vivo la detección de CSRF contra
  `tie.teziutlan.tecnm.mx` (Moodle). Ahora `--threads` se omite cuando
  hay `csrf_token` (sqlmap default a 1 thread, que es lo correcto acá:
  con threads > 1 el refresco del token podría pisarse entre requests
  concurrentes).
- `SqlmapRunner._detect_failure_reason` trataba la frase "target url
  content is not stable" como fallo fatal en cualquier parte del log,
  aunque sqlmap la recupera solo (marca el contenido dinámico, cambia
  a comparación por texto) y sigue probando la inyección real. Bug
  real encontrado contra `cloud.teziutlan.tecnm.mx` (login WebForms,
  cuyo VIEWSTATE/EVENTVALIDATION se regeneran en cada respuesta): un
  scan de 9+ minutos que corrió sqlmap de verdad y concluyó
  legítimamente "no vulnerable" se reportaba igual que un target
  inalcanzable ("DESCONOCIDO, no confiar en NO"), solo porque esa
  frase aparecía en algún punto del log. Confirmado corriendo sqlmap
  directo (sin el wrapper) contra el mismo request exacto: terminó un
  boolean-based blind real. Ahora ese marcador solo cuenta como fallo
  si el log nunca llega a "testing for sql injection on ..." después
  de la advertencia — si sqlmap sí probó el parámetro, el resultado se
  confía igual que cualquier otro scan limpio.
- `CommandBuilder.build` armaba `-p {param}` sin pasar por `shlex.quote`,
  a diferencia de todos los demás campos del comando (`url`, `data`,
  `cookie`, headers, proxy). Como `SqlmapRunner.run` ejecuta el comando
  final con `shell=True`, un nombre de parámetro con `$` literal —como
  `ctl00$cphContenido$txtNoControl`, la convención de nombrado de
  ASP.NET WebForms— se expandía como variable de entorno (vacía),
  truncando el parámetro real a `ctl00`. sqlmap no encontraba ese
  nombre en el POST real y terminaba en segundos reportando "no
  vulnerable" sin haber probado nada. Bug real encontrado contra
  `cloud.teziutlan.tecnm.mx` (login WebForms `frmLogin.aspx`).
- `WAFDetector._probe_waf_behavior` nunca revisaba el status code de
  su propia prueba de timing (`SLEEP(0)`) — solo medía el tiempo de
  respuesta. Bug real encontrado en `uttecam.edu.mx`: su WAF deja
  pasar `AND 1=1` y hasta un payload XSS con 200 limpio, pero bloquea
  la keyword `SLEEP(` específicamente con un 403 instantáneo (challenge
  JS anti-bot) — al no haber delay que medir, el bloqueo pasaba
  completamente desapercibido y el resultado quedaba en `waf=none`.
  Se extrajo la lógica de clasificación de "página de bloqueo" a un
  helper (`_classify_block_response`) reutilizado tanto por la prueba
  XSS como por la de timing.

### Agregado
- Descubrimiento automático de bypass de WAF (`WAFBypassProber`,
  `inyector/recon/waf_bypass_prober.py`): cuando el WAF detectado es de
  vendor desconocido (`unknown`/`keyword_sinkhole`) y sqlmap no
  confirmó nada, prueba empíricamente — con requests HTTP crudos,
  rápido, sin invocar sqlmap — una batería de mutaciones incrementales
  (una variable por vez: separador de espacio `/**/`/`+`/doble-espacio,
  case-randomization de la keyword, y aislar la keyword `SELECT` vía
  `scalarfuncbypass`) contra el target real, y si algo esquiva el
  bloqueo, reintenta sqlmap una vez más con esos tampers agregados
  (además escalando level/risk al máximo, dado que es el último
  intento de la corrida). Automatiza el mismo proceso de prueba A/B
  que se hizo a mano para encontrar los dos bypasses de
  itescam.edu.mx — `TamperSelector` ya tenía un fallback estático
  idéntico para WAF desconocido, pero lo aplicaba a ciegas sin validar
  si de verdad funciona contra el target puntual; este descubrimiento
  lo valida (o encuentra algo distinto) antes de comprometerse a una
  corrida completa. Reporta siempre qué se probó, nunca "no se pudo"
  en silencio — nuevo bloque `waf_bypass` en los tres formatos de
  reporte. Extraída la transformación de `scalarfuncbypass` a
  `inyector/utils/scalar_func_bypass.py` (lógica pura, sin depender de
  `lib.core.enums` de sqlmap) para que tanto el tamper real como el
  prober la usen sin duplicar código.
- Nuevo comando `dump`: enumeración/extracción persistente (`--current`,
  `--dbs`, `-D`/`--tables`, `-D -T`/`--columns`, `--dump`,
  `--dump-all`, `--search`) contra un target ya confirmado inyectable
  por un `scan` anterior. No reimplementa "recordar la técnica/DBMS
  confirmado" — sqlmap ya cachea eso solo en su propia sesión
  (`session.sqlite`), así que `dump` apunta al mismo `--output-dir`/
  URL/param/method y NO manda `--flush-session`
  (`CommandBuilder.build` ahora acepta `flush_session=False` para
  esto), dejando que sqlmap resuma la inyección ya confirmada en vez
  de re-detectar desde cero. Reintenta automáticamente antes de
  rendirse ("pentester persistente", no un solo intento): escala
  level/risk al máximo si el primer intento viene vacío, y para
  acciones de enumeración (baratas) fuerza una técnica a la vez
  (E→U→T→B→S) si sigue sin resultados — para `--dump`/`--dump-all`
  sobre una tabla completa solo se escala level/risk una vez, dado que
  probar 5 técnicas contra un boolean-blind puede tardar horas.
  Reporte: solo estructura y conteos (bases/tablas/columnas/filas
  encontradas), nunca los valores extraídos — esos quedan en el CSV
  que sqlmap ya genera por su cuenta bajo
  `<output_dir>/<host>/dump/<db>/<tabla>.csv` (decisión explícita de
  manejo de datos sensibles). Nuevo `inyector/reporting/dump_parser.py`
  (`DumpOutputParser`) para el output de este modo, separado de
  `SqlmapOutputParser` porque el modo dump imprime marcadores
  completamente distintos a los del modo detección.
- Detección automática de tokens anti-CSRF/dinámicos (`__VIEWSTATE`,
  `__EVENTVALIDATION`, `__RequestVerificationToken`, `csrfmiddlewaretoken`,
  `authenticity_token`, `csrf_token`, `_token`, `logintoken`, `sesskey`)
  en los `<form>` que descubre `--crawl`/`--crawl-all`, y wireado
  automático de `--csrf-token`/`--csrf-url`/`--csrf-method` en el
  comando sqlmap para que se refresquen antes de CADA request en vez
  de mandar siempre el mismo valor capturado una sola vez. Nuevo flag
  `--csrf-field`/`--csrf-url` para el flujo sin `--crawl` (cuando
  `-u`/`--data` se arman a mano). `KnowledgeBase` aprende qué campo
  funcionó por stack fingerprint (`record_csrf_field`/
  `get_known_csrf_field`) para sugerirlo en scans futuros contra otro
  target del mismo stack — solo como sugerencia en consola, nunca se
  auto-aplica.

  Motivado por dos casos reales: el `logintoken` de Moodle
  (`tie.teziutlan.tecnm.mx`) es de un solo uso — reusar un valor viejo
  re-renderiza el form vacío sin procesar el login, así que sin esto
  sqlmap no puede testear el endpoint en absoluto; el
  `__VIEWSTATE`/`__EVENTVALIDATION` de ASP.NET WebForms
  (`cloud.teziutlan.tecnm.mx`) se regenera en cada respuesta, lo cual
  confunde el check de estabilidad de sqlmap. Verificado empíricamente
  que sqlmap ya soporta refrescar estos tokens con `--csrf-token`/
  `--csrf-url` (no hacía falta un motor de testeo manual nuevo) —
  corriendo sqlmap directo contra el login de Moodle con estos flags,
  mandó ~10 valores de `logintoken` distintos y reales a lo largo del
  scan, uno por request.
- Tests unitarios para los módulos que no tenían ninguno: `waf_detector`,
  `stack_detector`, `orm_detector`, `graphql_detector`,
  `technique_selector`, `timing_calculator`, `enricher`, los tres
  generadores de reporte (HTML/JSON/Markdown), y los utils
  (`stealth`, `headers`, `session_store`, `signatures`,
  `response_compare`).
- CI: jobs de lint (`ruff`) y type-check (`mypy`), y job de seguridad
  (`gitleaks` para secretos, `pip-audit` para CVEs de dependencias).
- `.pre-commit-config.yaml` para correr `gitleaks`/`ruff` localmente
  antes de cada commit.
- `.github/dependabot.yml` (pip, github-actions, docker).
- Reintentos con backoff (3 intentos, solo en 502/503/504 — nunca en
  403/406/429, que son señal de WAF) en la sesión HTTP compartida.
- `--ai-max-calls`: tope configurable de llamadas a Gemini para toda
  la corrida (compartido entre targets con `--crawl-all`/`--targets-file`).
- `--targets-file`: escanear una lista de URLs desde un archivo, una
  por línea.
- Detección de WAF `keyword_sinkhole`: algunos WAFs institucionales sin
  firma de vendor conocida bloquean una keyword SQL con un 302 hacia
  un dominio completamente ajeno en vez de un 403 — un patrón que las
  firmas de vendor y los status codes de bloqueo directo no cubrían.
  Descubierto a mano contra `itescam.edu.mx`.
- Tamper propio de sqlmap `scalarfuncbypass` (`inyector/data/tampers/`,
  copiado a `/opt/sqlmap/tamper/` en el build de Docker): quita la
  keyword `SELECT` cuando antecede directo a una función escalar sin
  `FROM` (`DATABASE()`, `CURRENT_USER()`, `SUBSTRING()`...), para WAFs
  que bloquean `SELECT` sin importar el delimitador —
  `space2comment` solo no alcanza para ese caso. Se selecciona
  automáticamente para WAF `unknown` y `keyword_sinkhole`. Generaliza
  la técnica manual usada para confirmar y explotar la SQLi de
  `itescam.edu.mx` (4 intentos automatizados con sqlmap habían fallado
  ahí antes de esto).

### Cambiado
- `cli.py` (~1500 líneas, todos los comandos en un solo archivo) se
  partió en `inyector/commands/{scan,recon,report,version}.py` +
  `commands/common.py` (helpers compartidos: sesión HTTP, banner,
  tabla de resumen, generación de reportes). `cli.py` queda como
  entry point delgado que solo registra los comandos. Sin cambios de
  comportamiento — mismos flags, mismo output, mismos tests (solo se
  actualizaron los `monkeypatch` que apuntaban a rutas internas de
  `inyector.cli` para apuntar a la ubicación nueva).

### Corregido
- `stack_detector`: la firma de Django incluía el header
  `X-Frame-Options: SAMEORIGIN` (+3 puntos) — header que pone Django
  por default, pero también IIS/SharePoint, Apache, nginx y
  cualquier stack con hardening básico. No es discriminativo. Bug
  real encontrado en dos targets seguidos (`www.uat.edu.mx` en
  SharePoint/.NET y `repository.uaeh.edu.mx` en OJS/PHP): ambos
  ocultaban sus headers reveladores del stack real (hardening común)
  pero mantenían ese header genérico, y los dos se detectaban como
  "Django" solo por eso. Se sacó esa firma de headers — Django ahora
  se detecta solo por sus cookies (`csrftoken`/`sessionid`) y errores
  específicos.
- `_candidate_to_target` (comando `scan`, flujo `--crawl`/`--crawl-all`):
  para candidatos que vienen de un `<a href>` con query string propia
  (`crawler.py:_extract_links`), `url` ya trae esa query completa y
  `params` es el mismo query ya parseado — apendear `?k=v` de nuevo a
  ciegas producía una URL con dos `?` (ej.
  `...Authenticate.aspx?Source=%2F?Source=/`). Bug real encontrado en
  `www.uat.edu.mx` (SharePoint): esa URL rota se mandaba tal cual a
  sqlmap como target — el valor real del parámetro que se iba a
  probar quedaba corrompido antes de empezar. Ahora se mergea contra
  la query existente sin duplicar claves ya presentes; sigue
  agregando params normalmente para candidatos de `<form>`/rutas de
  API que no traen query propia.
- `payload_verifier`: la confirmación boolean-based comparaba la
  respuesta de un payload contra un baseline mandado con un valor
  sintético (`baseline_probe`), y confirmaba con una sola comparación
  sin control — bug real encontrado en `www.uag.mx` (endpoint de
  validación de email): 4 payloads de técnicas error/union-probe que
  nunca dispararon una firma de error de BD real se reportaron como
  "confirmados" solo porque cualquier valor con forma distinta al
  original hacía que el validador respondiera distinto; sqlmap, con
  testing diferencial real, marcó el mismo parámetro como false
  positive en el mismo run. Ahora el baseline usa el valor real
  original del parámetro, y antes de confirmar boolean-based se prueba
  un valor de control sin semántica SQL (misma forma/longitud que el
  payload) — si el control reproduce la misma diferencia, no se
  confirma (`signal: "inconclusive"`).
- `setup.py` no tenía la mitad de las dependencias reales de
  `requirements.txt` — el path de instalación sin Docker
  (`pip install -e .`) quedaba roto.
- README no documentaba `--websocket`, `--crawl-all` ni
  `--crawl-all-limit`, ya implementados en el código.
- ~50 errores de tipos reales detectados por `mypy` (valores `None`
  en parámetros no-`Optional`, dicts/tuplas heterogéneos sin anotar
  que colapsaban a `object`) y ~20 imports/variables sin usar
  detectados por `ruff`.
- Bump de dependencias con CVEs conocidas: `click` 8.1.7→8.3.3,
  `requests` 2.31.0→2.33.0, `urllib3` 2.2.1→2.7.0, `jinja2`
  3.1.3→3.1.6, `brotli` 1.1.0→1.2.0, `pytest` 8.0.0→9.0.3 (dev).

### Seguridad
- `har/` (capturas de tráfico con datos reales de sesión) agregado a
  `.gitignore` — no debe terminar versionado.

## [1.0.0] - 2026-07-20

Baseline reconstruido de los commits previos a este changelog (nunca
se tagueó formalmente, pero es lo que `setup.py` venía declarando).

### Agregado
- Reconocimiento inteligente: fingerprinting de WAF (~28 vendors),
  detección de stack tecnológico y de 7 ORMs, soporte nativo de
  GraphQL (descubrimiento de endpoints, introspección, fingerprint de
  motor), detección de NoSQL injection (operator/`$where`) con motor
  propio (sqlmap no soporta NoSQL).
- Modo stealth: timing gaussiano, rotación de headers, pausas
  automáticas por WAF.
- Crawler de sitio (links, forms, rutas de API embebidas en JS) para
  SPAs sin parámetros en la URL — con extracción de candidatos y
  priorización por vector de ataque.
- Reportes HTML (dark theme), JSON y Markdown con recomendaciones de
  remediación por ORM/stack.
- Asistente de IA opcional (Gemini) con memoria de técnicas aprendidas
  (`KnowledgeBase`) y bitácora de auditoría completa de cada decisión
  (`AIAuditLog`) — nunca se reporta nada como hallazgo solo porque el
  modelo lo sugirió, todo se re-verifica contra el target real.
- Empaquetado 100% Docker (`docker compose run inyector scan ...`).

### Corregido
- Deadlock real del spinner de consola durante corridas largas de
  sqlmap (dos hilos actualizando `rich.Live` al mismo tiempo).
- Decodificación de Brotli (`Content-Encoding: br`) — sin esto, todos
  los detectores por substring fallaban en silencio contra sitios
  modernos detrás de CDN.
- Bugs de shell-quoting en la construcción del comando sqlmap.
