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
