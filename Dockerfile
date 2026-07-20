FROM python:3.11-slim

LABEL maintainer="TribuCibernetica <hola@tribucibernetica.com>"
LABEL description="inyector — SQL Injection Intelligence Tool"
LABEL version="1.0.0"

# Sin esto, TERM queda vacío dentro del contenedor cuando el host es
# Windows (PowerShell no tiene el concepto de $TERM de Unix), y Rich
# (nuestra librería de UI) decide que no hay terminal real y deja de
# refrescar el spinner en vivo — se ve exactamente igual a un cuelgue,
# aunque sqlmap siga corriendo perfectamente de fondo.
ENV TERM=xterm-256color

# Dependencias del sistema
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nmap \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Instalar sqlmap desde repositorio oficial
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git \
    /opt/sqlmap

# Hacer sqlmap ejecutable globalmente
RUN echo '#!/bin/bash\npython3 /opt/sqlmap/sqlmap.py "$@"' \
    > /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código
COPY inyector/ ./inyector/

# Instalar inyector como paquete
COPY setup.py .
RUN pip install -e .

# Volumen para reportes
VOLUME ["/app/reports"]

# Punto de entrada
ENTRYPOINT ["inyector"]
CMD ["--help"]
