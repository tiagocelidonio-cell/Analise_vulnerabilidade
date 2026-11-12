FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Dependencias de sistema: build, libs do WeasyPrint, nmap e utilitarios.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    nmap curl unzip ca-certificates \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev libcairo2 shared-mime-info fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

# Ferramentas ProjectDiscovery (nuclei = vulnerabilidades, subfinder = subdominios).
ARG NUCLEI_VERSION=3.3.5
ARG SUBFINDER_VERSION=2.6.6
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in arm64) A=arm64;; *) A=amd64;; esac; \
    curl -sSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${A}.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    curl -sSL -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${A}.zip"; \
    unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin; \
    rm -f /tmp/*.zip; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder

# Baixa os templates do nuclei (melhor esforco; senao baixa na 1a execucao).
RUN nuclei -update-templates -disable-update-check 2>/dev/null || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
