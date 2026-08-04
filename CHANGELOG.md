# Changelog

Todos los cambios notables de este proyecto se documentan acá.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto usa [Semantic Versioning](https://semver.org/lang/es/):
`MAJOR.MINOR.PATCH` — MAJOR para cambios incompatibles, MINOR para
funcionalidad nueva compatible hacia atrás, PATCH para fixes.

## [Unreleased]

Todavía no tagueado — se convierte en `1.1.0` (MINOR: solo agrega,
nada rompe compatibilidad) cuando se commitee y se taguee.

### Agregado
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
