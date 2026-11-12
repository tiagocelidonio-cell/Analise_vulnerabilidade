FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Dependencias de sistema: build, libs do WeasyPrint, nmap e utilitarios.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    nmap curl unzip git ca-certificates \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev libcairo2 shared-mime-info fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

# Base LOCAL de CVE para o nmap (vulscan): bancos CSV de CVE embutidos ->
# o nmap correlaciona versao->CVE OFFLINE (sem vulners.com/internet no scan).
RUN git clone --depth 1 https://github.com/scipag/vulscan \
    /usr/share/nmap/scripts/vulscan 2>/dev/null || true

# Ferramentas: nuclei (vulns), subfinder + amass (subdominios).
ARG NUCLEI_VERSION=3.3.5
ARG SUBFINDER_VERSION=2.6.6
ARG AMASS_VERSION=4.2.0
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in arm64) A=arm64;; *) A=amd64;; esac; \
    curl -sSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${A}.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    curl -sSL -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${A}.zip"; \
    unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin; \
    curl -sSL -o /tmp/amass.zip "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${A}.zip"; \
    unzip -o -j /tmp/amass.zip "amass_Linux_${A}/amass" -d /usr/local/bin; \
    rm -f /tmp/*.zip; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/amass

# Baixa os templates do nuclei (melhor esforco; senao baixa na 1a execucao).
RUN nuclei -update-templates -disable-update-check 2>/dev/null || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
