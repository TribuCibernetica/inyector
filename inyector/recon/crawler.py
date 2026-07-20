"""Módulo de crawling/descubrimiento de endpoints.

Sin esto, inyector solo puede probar la URL exacta que el usuario le
da — si esa URL no tiene parámetros (ej. la landing page de una SPA
de Angular/React como OWASP Juice Shop), sqlmap no tiene nada que
inyectar y el scan termina en "no parameter(s) found for testing",
aunque el sitio esté lleno de endpoints reales e inyectables un click
más adentro.

El Crawler descubre esos endpoints de tres formas:
1. Links y forms en el HTML servido (sitios tradicionales).
2. Rutas de API embebidas en los bundles de JS (`<script src=...>`) —
   el vector que de verdad hace falta para SPAs modernas, donde el
   HTML inicial no tiene ningún link ni form real, pero el JS
   compilado sí contiene las rutas REST/API hardcodeadas
   (ej. '/rest/user/login', '/api/Products').
3. Probing liviano de esas rutas con parámetros comunes (q, id,
   search, email+password) para confirmar cuáles responden de forma
   significativa antes de proponerlas como candidatas a testear.
"""

import json
import re
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class Crawler:
    """Descubre endpoints y parámetros candidatos dentro de un sitio."""

    # Prefijos de ruta típicos de APIs REST/GraphQL modernas.
    API_PATH_PATTERN = re.compile(
        r"""["'](/(?:rest|api|graphql|v[0-9]+)/[a-zA-Z0-9_\-/]*)["']""",
        re.IGNORECASE,
    )

    COMMON_GET_PARAMS = ["q", "search", "id", "query", "term", "keyword"]

    COMMON_JSON_BODIES = [
        {"email": "inyector@test.com", "password": "Test1234!"},
        {"username": "inyector", "password": "Test1234!"},
        {"query": "test"},
        {"id": 1},
    ]

    # Rutas cuyo nombre sugiere que vale la pena priorizarlas (login,
    # búsqueda, etc. son los vectores clásicos de SQLi/NoSQLi).
    HIGH_VALUE_HINTS = [
        "login", "auth", "search", "query", "user", "product",
        "account", "signin", "session",
    ]

    def crawl(self, base_url: str, session: requests.Session,
              max_pages: int = 5, max_js_files: int = 6,
              max_api_paths_to_probe: int = 15) -> list[dict]:
        """Descubre endpoints candidatos a partir de una URL base.

        Args:
            base_url: URL de arranque del crawl.
            session: Sesión HTTP configurada.
            max_pages: Máximo de páginas HTML a visitar.
            max_js_files: Máximo de archivos JS a inspeccionar.
            max_api_paths_to_probe: Máximo de rutas de API a probar
                con parámetros comunes.

        Returns:
            Lista de candidatos, cada uno:
            {
                "url": str, "method": "GET"|"POST",
                "params": {nombre: valor} | None,
                "json_body": dict | None,
                "source": "html_link"|"html_form"|"js_api_path",
                "priority": float (0.0-1.0, mayor = más prometedor),
            }
        """
        logger.info(f"Iniciando crawl de {base_url}...")

        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        candidates: list[dict] = []
        visited_pages: set[str] = set()
        js_urls: set[str] = set()

        pages_to_visit = [base_url]

        base_page_failed = False

        while pages_to_visit and len(visited_pages) < max_pages:
            page_url = pages_to_visit.pop(0)
            if page_url in visited_pages:
                continue
            visited_pages.add(page_url)

            # Timeout más generoso para la página base: si el sitio
            # está lento (no caído), un timeout corto la descarta y
            # el crawl termina "sin candidatos" — indistinguible de
            # que el sitio genuinamente no tenga nada, que es
            # exactamente el tipo de falso negativo silencioso que
            # venimos corrigiendo en el resto de la herramienta.
            html = self._fetch_text(page_url, session, timeout=30)
            if html is None:
                if page_url == base_url:
                    base_page_failed = True
                    logger.warning(
                        f"No se pudo cargar la página base ({page_url}) — "
                        f"el crawl NO es confiable, esto no significa que "
                        f"el sitio no tenga endpoints"
                    )
                continue

            soup = BeautifulSoup(html, "html.parser")

            for link_candidate, next_page in self._extract_links(
                page_url, origin, soup,
            ):
                if link_candidate:
                    candidates.append(link_candidate)
                if next_page and next_page not in visited_pages:
                    pages_to_visit.append(next_page)

            candidates.extend(self._extract_forms(page_url, origin, soup))

            for script in soup.find_all("script", src=True):
                js_url = urljoin(page_url, script["src"])
                if urlparse(js_url).netloc == parsed_base.netloc:
                    js_urls.add(js_url)

        # Rutas de API escondidas en el JS compilado — el vector que
        # importa para SPAs (Angular/React/Vue) sin HTML server-side.
        api_paths: set[str] = set()
        for js_url in list(js_urls)[:max_js_files]:
            js_text = self._fetch_text(js_url, session, timeout=30)
            if not js_text:
                logger.debug(f"No se pudo descargar JS: {js_url}")
                continue
            for match in self.API_PATH_PATTERN.finditer(js_text):
                path = match.group(1).rstrip("/")
                if path and len(path) > 1:
                    api_paths.add(path)

        logger.info(
            f"Crawl encontró {len(candidates)} candidatos en HTML y "
            f"{len(api_paths)} rutas de API en {len(js_urls)} archivo(s) JS"
        )

        # Ordenar por prioridad ANTES de truncar — si no, un corte
        # alfabético descarta rutas reales importantes como
        # '/rest/user/login' solo porque '/api/...' viene antes en el
        # alfabeto (bug real encontrado probando contra Juice Shop).
        prioritized_paths = sorted(
            api_paths,
            key=lambda p: (
                0 if any(hint in p.lower() for hint in self.HIGH_VALUE_HINTS) else 1,
                p,
            ),
        )
        probed = self._probe_api_paths(
            origin, prioritized_paths[:max_api_paths_to_probe], session,
        )
        candidates.extend(probed)

        for c in candidates:
            c["priority"] = self._score(c)

        candidates.sort(key=lambda c: c["priority"], reverse=True)

        deduped = self._dedupe(candidates)
        logger.info(f"Crawl finalizado: {len(deduped)} candidato(s) únicos")
        return deduped

    def _fetch_text(self, url: str, session: requests.Session,
                     timeout: int = 15) -> Optional[str]:
        try:
            response = session.get(url, timeout=timeout)
            if response.status_code < 400:
                return response.text
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error crawleando {url}: {e}")
        return None

    def _extract_links(self, page_url: str, origin: str,
                       soup: BeautifulSoup):
        """Extrae <a href> same-origin, separando los que ya traen
        query string (candidatos directos) de los que hay que seguir
        crawleando."""
        results = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue

            full_url = urljoin(page_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc != urlparse(origin).netloc:
                continue

            if parsed.query:
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                candidate = {
                    "url": full_url, "method": "GET", "params": params,
                    "json_body": None, "source": "html_link",
                }
                results.append((candidate, None))
            else:
                results.append((None, full_url.split("#")[0]))

        return results

    def _extract_forms(self, page_url: str, origin: str,
                       soup: BeautifulSoup) -> list[dict]:
        candidates = []
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            full_url = urljoin(page_url, action)
            if urlparse(full_url).netloc != urlparse(origin).netloc:
                continue

            method = (form.get("method") or "GET").upper()
            params = {}
            for field in form.find_all(["input", "textarea"]):
                name = field.get("name")
                if not name:
                    continue
                params[name] = field.get("value") or "test"

            if not params:
                continue

            candidates.append({
                "url": full_url, "method": method,
                "params": params if method == "GET" else None,
                "json_body": None if method == "GET" else params,
                "source": "html_form",
            })

        return candidates

    def _probe_api_paths(self, origin: str, api_paths: list[str],
                         session: requests.Session) -> list[dict]:
        """Prueba rutas de API descubiertas en JS con parámetros
        comunes, para confirmar cuáles aceptan input antes de
        proponerlas (en vez de adivinar a ciegas)."""
        found = []

        for path in api_paths:
            url = f"{origin}{path}"

            # Candidato GET con cada parámetro común
            for param_name in self.COMMON_GET_PARAMS:
                test_url = f"{url}?{param_name}=inyector_probe"
                response = self._safe_get(session, test_url)
                if response is not None and response.status_code not in (404, 405):
                    found.append({
                        "url": url, "method": "GET",
                        "params": {param_name: "test"},
                        "json_body": None, "source": "js_api_path",
                    })
                    break  # un param que responde ya alcanza para este path

            # Candidato POST/JSON con cuerpos comunes
            for body in self.COMMON_JSON_BODIES:
                try:
                    response = session.post(url, json=body, timeout=15)
                except requests.exceptions.RequestException:
                    continue
                if response.status_code not in (404, 405):
                    found.append({
                        "url": url, "method": "POST",
                        "params": None, "json_body": body,
                        "source": "js_api_path",
                    })
                    break

        return found

    def _safe_get(self, session, url):
        try:
            return session.get(url, timeout=15)
        except requests.exceptions.RequestException:
            return None

    def _score(self, candidate: dict) -> float:
        score = 0.3
        url_lower = candidate["url"].lower()

        if any(hint in url_lower for hint in self.HIGH_VALUE_HINTS):
            score += 0.4

        # "login" es, históricamente, el vector individual más
        # significativo de SQLi/NoSQLi (bypass de autenticación) —
        # desempata a favor suyo cuando varios candidatos empatan en
        # la puntuación genérica de arriba. Exigimos que sea un
        # SEGMENTO de path exacto (ej. '/rest/user/login'), no
        # cualquier substring — si no, algo como '/rest/saveLoginIp'
        # (que no es un login real) empata con el login de verdad y
        # gana por orden de inserción (bug real encontrado probando
        # contra Juice Shop).
        path_segments = urlparse(url_lower).path.strip("/").split("/")
        if "login" in path_segments:
            score += 0.15

        param_count = len(candidate.get("params") or candidate.get("json_body") or {})
        score += min(0.3, param_count * 0.1)

        if candidate["source"] == "html_form":
            score += 0.1

        return min(1.0, score)

    def _dedupe(self, candidates: list[dict]) -> list[dict]:
        seen = set()
        result = []
        for c in candidates:
            key = (
                c["url"], c["method"],
                tuple(sorted((c.get("params") or {}).keys())),
                tuple(sorted((c.get("json_body") or {}).keys())),
            )
            if key not in seen:
                seen.add(key)
                result.append(c)
        return result
