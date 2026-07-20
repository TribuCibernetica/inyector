# ⟁ inyector

> **SQL Injection Intelligence Tool** — by TribuCibernetica

![Python 3.11](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)
![License MIT](https://img.shields.io/badge/License-MIT-green)
![Solo Uso Autorizado](https://img.shields.io/badge/⚠️-Solo_Uso_Autorizado-red)

---

## ¿Qué es inyector?

**inyector** es una herramienta de reconocimiento y detección de SQL Injection que orquesta **sqlmap** de manera inteligente. A diferencia de usar sqlmap directamente, inyector realiza un reconocimiento previo del objetivo para:

- 🔍 **Fingerprinting de WAF** — Detecta automáticamente Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, Wordfence, Sucuri, F5 y Barracuda
- 🧠 **Selección inteligente de tamper scripts** — Elige los scripts de evasión óptimos según el WAF detectado
- 🏗️ **Detección de stack tecnológico** — Identifica lenguaje, framework y base de datos
- 🔧 **Detección de ORM** — Identifica Django ORM, SQLAlchemy, Hibernate, Prisma, Sequelize, ActiveRecord y Eloquent
- 🕸️ **Soporte GraphQL nativo** — Descubre endpoints, verifica introspección y encuentra argumentos inyectables
- 🥷 **Modo stealth avanzado** — Timing con distribución gaussiana, rotación de headers y pausas automáticas
- 📊 **Reportes HTML ejecutivos** — Reportes profesionales con tema oscuro y recomendaciones de remediación

## Requisitos

**Solo Docker.** No necesitas instalar Python, sqlmap ni ninguna otra dependencia.

```bash
docker --version
docker compose version
```

## Instalación

```bash
git clone https://github.com/tribucibernetica/inyector
cd inyector
docker compose build
```

## Uso

### Scan básico

```bash
docker compose run inyector scan -u "https://target.com/page?id=1"
```

### Con modo sigilo

```bash
docker compose run inyector scan \
  -u "https://target.com/page?id=1" \
  --stealth \
  --format html
```

### Scan con parámetro específico

```bash
docker compose run inyector scan \
  -u "https://target.com/search" \
  --method POST \
  --data "query=test&page=1" \
  -p query \
  --stealth
```

### Auditoría GraphQL

```bash
docker compose run inyector scan \
  -u "https://target.com" \
  --graphql \
  --stealth
```

### Explorar el sitio antes de escanear (SPAs, apps sin params en la URL)

```bash
docker compose run inyector scan \
  -u "https://target.com/" \
  --crawl \
  --stealth
```

### Con asistente de IA (segunda opinión cuando sqlmap no encuentra nada)

```bash
docker compose run inyector scan \
  -u "https://target.com/page?id=1" \
  --ai-assist \
  --stealth
```

Requiere una API key de Gemini configurada — ver [Asistente de IA (opcional)](#asistente-de-ia-opcional) más abajo.

### Solo reconocimiento (sin sqlmap)

```bash
docker compose run inyector recon \
  -u "https://target.com/page?id=1"
```

### Generar reporte desde resultados previos

```bash
docker compose run inyector report \
  --input /app/reports/scan_20260717.json \
  --format html
```

### Ver versión

```bash
docker compose run inyector version
```

### Acceder a los reportes

Los reportes se guardan automáticamente en `./reports/` en tu máquina local:

```bash
open reports/scan_*.html       # macOS
xdg-open reports/scan_*.html   # Linux
start reports\scan_*.html      # Windows
```

## Opciones completas

| Opción | Descripción | Default |
|--------|-------------|----------|
| `-u, --url` | URL objetivo (requerido) | — |
| `-p, --param` | Parámetro específico a testear | auto |
| `--method` | Método HTTP (GET/POST) | GET |
| `--data` | Datos para POST | — |
| `--cookie` | Cookies de sesión | — |
| `--header` | Headers adicionales (múltiple) | — |
| `--stealth` | Modo sigilo máximo | off |
| `--fast` | Sin modo sigilo | off |
| `--waf` | Forzar WAF (cloudflare/aws/modsec/imperva/akamai/wordfence/sucuri/f5/barracuda/aws_cloudfront/citrix_netscaler/fortiweb/fortigate/palo_alto/radware/distil/perimeterx/stackpath/reblaze/vercel/zenedge/edgecast/dotdefender/naxsi/comodo/sitelock/none) | auto |
| `--technique` | Forzar técnica SQLi (B/E/U/S/T/Q) | auto |
| `--tamper` | Tamper scripts adicionales | auto |
| `--threads` | Threads para sqlmap | 3 |
| `--level` | Level sqlmap (1-5) | 2 |
| `--risk` | Risk sqlmap (1-3) | 1 |
| `--output-dir` | Directorio de reportes | /app/reports |
| `--format` | Formato: html, json, markdown, all | all |
| `--graphql` | Activar módulo GraphQL | off |
| `--nosql` | Activar detección de NoSQL injection (MongoDB): operator injection ($ne/$eq) y $where injection. sqlmap no soporta NoSQL, así que corre con motor propio | off |
| `--crawl` | Explorar el sitio (links, forms, y rutas de API embebidas en JS) antes de escanear. Necesario cuando la URL no tiene parámetros propios, ej. la landing page de una SPA Angular/React/Vue | off |
| `--ai-assist` | Segunda opinión con IA (Gemini) cuando sqlmap no encuentra nada. Requiere `GEMINI_API_KEY` — ver [Asistente de IA](#asistente-de-ia-opcional) | off |
| `--resume` | Reusar el recon guardado de un scan anterior al mismo target (evita repetir WAF/Stack/ORM/GraphQL) | off |
| `--no-sqlmap` | Solo reconocimiento | off |
| `--proxy` | Proxy HTTP | — |
| `--tor` | Enrutar por Tor | off |
| `-v, --verbose` | Output detallado | off |
| `-q, --quiet` | Solo resultados finales | off |

## Diferencias con sqlmap puro

| Característica | sqlmap | inyector |
|---|---|---|
| Fingerprinting WAF automático | ❌ No | ✅ Sí |
| Selección de tamper por WAF | Manual | ✅ Automático |
| Detección de ORM | ❌ No | ✅ 7 ORMs |
| Soporte GraphQL nativo | Limitado | ✅ Completo |
| Modo stealth con timing humano | Básico | ✅ Avanzado |
| Reporte HTML ejecutivo | ❌ No | ✅ Dark theme |
| Recomendaciones de remediación | ❌ No | ✅ Por ORM/Stack |
| Zero-install (Docker) | ❌ No | ✅ Un comando |

## Asistente de IA (opcional)

`--ai-assist` le da al pipeline una "segunda opinión" cuando sqlmap
(con la configuración estándar) no encuentra nada, o termina en un
resultado ambiguo (ej. `target url content is not stable`, común en
APIs que devuelven un JWT/timestamp distinto en cada respuesta). Usa
[Gemini](https://ai.google.dev/) para sugerir payloads avanzados y
específicos del stack/ORM detectado — pensados para cubrir el "long
tail" de casos que normalmente solo un pentester experimentado
probaría a mano (second-order injection, bypass específico de un ORM,
contextos poco comunes como headers/cookies).

**Es 100% opt-in.** Sin `--ai-assist`, o sin `GEMINI_API_KEY`
configurada, inyector funciona exactamente igual que siempre — el
pipeline determinista (WAF/tamper/técnica) nunca depende de esto.

### Cómo funciona (y por qué no gasta tokens de más)

1. **Memoria de técnicas aprendidas primero.** Antes de llamar a
   Gemini, se consulta una base de conocimiento local
   (`reports/.inyector_knowledge/`) por técnicas que ya se confirmaron
   como exitosas contra un fingerprint de stack parecido (mismo
   framework + ORM + WAF + DBMS, sin importar el dominio). Si hay algo
   conocido, se prueba primero — gratis, sin llamar a la API.
2. **Solo si nada conocido funciona**, se le pide a Gemini una
   sugerencia nueva, con el contexto real del target (stack, ORM, WAF,
   un fragmento de respuesta real).
3. **Nada se reporta como hallazgo solo porque el modelo lo sugirió.**
   Cada sugerencia se prueba contra el target real (firma de error de
   BD, delay de tiempo, o cambio de comportamiento) antes de contar
   como confirmada.
4. **Lo que se confirma, se aprende.** Se guarda en la base de
   conocimiento para la próxima vez que aparezca un stack parecido —
   con el tiempo, cada vez se depende menos de la API.

### Configuración

1. Conseguí una API key gratuita en [Google AI Studio](https://aistudio.google.com/apikey).
2. Copiá `.env.example` a `.env` y completá tu key:

   ```bash
   cp .env.example .env
   # editá .env y pegá tu GEMINI_API_KEY
   ```

3. `.env` **nunca se sube a git** (ya está en `.gitignore`) — es tuyo, local.
4. Usá `--ai-assist` en tu scan:

   ```bash
   docker compose run inyector scan -u "https://target.com/page?id=1" --ai-assist
   ```

### ⚠️ Antes de activarlo

Con `--ai-assist`, se manda a la API de Gemini (Google): la URL del
target, el stack/ORM/WAF detectado, y fragmentos de respuestas reales
del sitio. Para la mayoría de pentests/CTFs/bug bounties autorizados
esto no es un problema, pero es una decisión que el alcance de tu
auditoría debería contemplar explícitamente — no es algo para activar
por default sin pensarlo. El pipeline central (WAF/tamper/técnica)
nunca manda nada a nadie, con o sin `--ai-assist`.

## Casos de uso

### CTFs y laboratorios

```bash
docker compose run inyector scan \
  -u "http://ctf.local/vuln.php?id=1" \
  --fast --level 5 --risk 3
```

### Bug Bounty

```bash
docker compose run inyector scan \
  -u "https://target.com/api/users?id=1" \
  --stealth \
  --proxy http://127.0.0.1:8080 \
  --format all
```

### Pentesting autorizado

```bash
docker compose run inyector scan \
  -u "https://app.client.com/dashboard?user=1" \
  --cookie "session=AUTH_TOKEN" \
  --graphql \
  --stealth \
  --format html
```

## ⚠️ Disclaimer

Esta herramienta es **solo para uso en entornos autorizados**. Ver [DISCLAIMER.md](DISCLAIMER.md) para el aviso legal completo.

## Testing

```bash
# Tests unitarios (rápidos, sin Docker)
pip install -r requirements-dev.txt
pytest tests/ --ignore=tests/integration

# Tests de integración (levantan labs reales con Docker: PHP+MySQL y Express+MongoDB)
pytest tests/integration/ -v
```

CI corre ambos automáticamente en cada push/PR (ver `.github/workflows/test.yml`).

## Contribuir

1. Fork el repositorio
2. Crea tu branch: `git checkout -b feature/mi-feature`
3. Commit: `git commit -am 'Agregar mi feature'`
4. Push: `git push origin feature/mi-feature`
5. Abre un Pull Request

## Créditos

- [sqlmap project](https://sqlmap.org) — Motor de detección de SQL Injection
- [TribuCibernetica](https://tribucibernetica.com) — Wrapper, reconocimiento e inteligencia

---

*Desarrollado con 🧠 por [TribuCibernetica](https://tribucibernetica.com) — hola@tribucibernetica.com*
