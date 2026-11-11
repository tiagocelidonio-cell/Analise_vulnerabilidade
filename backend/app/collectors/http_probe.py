"""Coletor web: fingerprint HTTP, TLS e security headers.

Cobre o lado "web app" do alvo. Produz:
- um fato de servico HTTP (com o header Server, que realimenta a correlacao CVE)
- um fato por security header ausente (vira achado de baixa severidade)
- um fato de certificado TLS proximo do vencimento / invalido

Resiliente: alvo que nao responde simplesmente nao gera fatos.
"""
from __future__ import annotations

import asyncio
import re
import ssl
from datetime import datetime, timezone

import httpx

from app.collectors.base import CollectedFact
from app.config import settings

_HTTP_PORTS = {80, 8000, 8080, 3000, 9000}
_HTTPS_PORTS = {443, 8443}

# Headers de seguranca esperados -> descricao do risco se ausente.
_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy ausente (risco de XSS/injecao).",
    "x-frame-options": "X-Frame-Options ausente (risco de clickjacking).",
    "x-content-type-options": "X-Content-Type-Options ausente (MIME sniffing).",
    "referrer-policy": "Referrer-Policy ausente (vazamento de referer).",
}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _scheme_for(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


async def _tls_cert_fact(host: str, port: int, timeout: float) -> CollectedFact | None:
    """Conecta via TLS e checa validade do certificado."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # scanner precisa inspecionar cert invalido tambem
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None

    cert = writer.get_extra_info("peercert")
    ssl_obj = writer.get_extra_info("ssl_object")
    # peercert vem vazio com CERT_NONE; pega via getpeercert(binary)->parse basico
    not_after = None
    if ssl_obj is not None:
        try:
            cert = ssl_obj.getpeercert()
            not_after = cert.get("notAfter") if cert else None
        except (ValueError, AttributeError):
            not_after = None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass

    if not not_after:
        return None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None

    days = (exp - datetime.now(timezone.utc)).days
    if days < 0:
        title, hint = f"Certificado TLS EXPIRADO em {host}:{port}", "high"
    elif days < 30:
        title, hint = f"Certificado TLS vence em {days} dias ({host}:{port})", "medium"
    else:
        return None  # cert saudavel nao e achado
    return CollectedFact(
        target=host, port=port, service="tls",
        title=title, raw=f"notAfter={not_after}",
        data={"severity_hint": hint, "not_after": not_after},
    )


async def _probe_url(host: str, port: int, timeout: float) -> list[CollectedFact]:
    scheme = _scheme_for(port)
    url = f"{scheme}://{host}:{port}/"
    facts: list[CollectedFact] = []
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=True
        ) as client:
            resp = await client.get(url)
    except (httpx.HTTPError, OSError):
        return facts

    headers = {k.lower(): v for k, v in resp.headers.items()}
    server = headers.get("server", "")
    title_m = _TITLE_RE.search(resp.text or "")
    title = (title_m.group(1).strip()[:120] if title_m else "")

    # Fato de servico HTTP (Server header realimenta a correlacao CVE).
    facts.append(
        CollectedFact(
            target=host, port=port, service=scheme,
            title=f"Servico {scheme.upper()} ({server or 'sem Server header'})",
            raw=f"Server: {server}\nStatus: {resp.status_code}\nTitle: {title}",
            data={"banner": f"Server: {server}", "status": resp.status_code,
                  "title": title, "server": server},
        )
    )

    # Um fato por security header ausente.
    for header, risk in _SECURITY_HEADERS.items():
        if header not in headers:
            facts.append(
                CollectedFact(
                    target=host, port=port, service=scheme,
                    title=f"{header} ausente em {host}:{port}",
                    raw=risk,
                    data={"severity_hint": "low", "weakness": header},
                )
            )
    # HSTS so faz sentido em https.
    if scheme == "https" and "strict-transport-security" not in headers:
        facts.append(
            CollectedFact(
                target=host, port=port, service=scheme,
                title=f"HSTS ausente em {host}:{port}",
                raw="Strict-Transport-Security ausente (downgrade/MITM).",
                data={"severity_hint": "low", "weakness": "hsts"},
            )
        )
    return facts


class HttpProbeCollector:
    name = "http_probe"

    async def run(
        self, targets: list[str], ports: list[int] | None = None, **kwargs
    ) -> list[CollectedFact]:
        ports = ports or sorted(_HTTP_PORTS | _HTTPS_PORTS)
        timeout = settings.scan_connect_timeout * 2
        sem = asyncio.Semaphore(settings.scan_max_concurrency)
        out: list[CollectedFact] = []

        async def guarded(host: str, port: int) -> None:
            async with sem:
                out.extend(await _probe_url(host, port, timeout))
                if port in _HTTPS_PORTS:
                    cert = await _tls_cert_fact(host, port, timeout)
                    if cert:
                        out.append(cert)

        await asyncio.gather(*(guarded(h, p) for h in targets for p in ports))
        return out
