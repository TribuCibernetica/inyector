
3. Pruebas realizadas (todas en Docker, no local)

- docker compose build → build limpio.
- inyector --help, inyector version (detecta sqlmap 1.10.7.110#dev instalado) → ver output abajo.
- inyector recon -u ... contra httpbin.org → flujo de reconocimiento completo (WAF/Stack/ORM) funcionando.
- inyector scan --no-sqlmap → generación de reportes HTML+JSON, verificados en ./reports/ del host (el volumen funciona).
- inyector scan completo con sqlmap real contra un laboratorio propio de SQLi ciego (POST) → ejecución de sqlmap, parseo de "no vulnerable", reporte correcto.
- inyector report --input ... → genera reporte desde JSON existente.

No hubo dependencias adicionales necesarias — el requirements.txt y Dockerfile originales fueron suficientes.

4. Output de --help y version

Usage: inyector [OPTIONS] COMMAND [ARGS]...

  inyector — SQL Injection Intelligence Tool by TribuCibernetica.

Commands:
  recon    Ejecuta solo el reconocimiento sin sqlmap.
  report   Genera un reporte a partir de resultados existentes.
  scan     Ejecuta un scan completo de SQL Injection.
  version  Muestra la versión de inyector y sqlmap.

  inyector  v1.0.0
  sqlmap   1.10.7.110#dev

5. Cómo hacer tu primer scan

cd inyector
docker compose build          # solo la primera vez o tras cambios en código
docker compose run --rm inyector scan -u "http://TARGET/page?id=1" --stealth --format all
Los reportes aparecen en ./reports/ en tu máquina (montado como volumen). Nota: usé --rm en mis pruebas para no dejar contenedores huérfanos — te recomiendo lo mismo.

Un detalle menor respecto al spec original: el CLI implementado usa --format html|json|all (sin markdown), ya que no se construyó un generador de markdown — solo hay html_report.py y json_report.py. Si quieres que agregue soporte de Markdown, lo puedo hacer.