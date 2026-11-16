"""Interface de coletor. Todo coletor produz FATOS estruturados, nunca opinioes.

A IA so raciocina depois, sobre o que o coletor provou. Qualquer ferramenta
externa (masscan, nuclei, ...) pode virar um coletor implementando isto.
"""
from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Protocol

import httpx


async def http_fetch(
    url: str,
    timeout: float,
    max_body: int = 65536,
    headers: dict | None = None,
    verify: bool = False,
    follow_redirects: bool = True,
) -> tuple[int, dict, str] | None:
    """GET resiliente para coletores web. Retorna (status, headers, texto) ou None.

    Blinda contra o que TRAVAVA os scans: um host da rede (camera/roteador) que
    aceita a conexao e envia o corpo em streaming/trickle fazia o cliente ler
    para sempre. Aqui:
    - le NO MAXIMO `max_body` bytes do corpo (suficiente p/ <title>/assinaturas);
    - aplica TETO DE TEMPO de parede (`wait_for`), entao nenhum probe pende;
    - limita redirecionamentos.
    Headers vem em minusculas. Nunca levanta excecao (coletor so ignora o host)."""
    tmo = httpx.Timeout(timeout, connect=timeout, read=timeout, write=timeout, pool=timeout)

    async def _go() -> tuple[int, dict, str]:
        async with httpx.AsyncClient(
            verify=verify, timeout=tmo, follow_redirects=follow_redirects,
            max_redirects=5,
            headers=headers or {"User-Agent": "Mozilla/5.0 VulnScope"},
        ) as client:
            async with client.stream("GET", url) as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= max_body:
                        break
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status_code, hdrs, bytes(body).decode("utf-8", "ignore")

    try:
        return await asyncio.wait_for(_go(), timeout=timeout * 3 + 2)
    except (httpx.HTTPError, OSError, asyncio.TimeoutError, ssl.SSLError,
            UnicodeError):
        return None


@dataclass
class CollectedFact:
    target: str
    port: int | None = None
    service: str | None = None
    title: str = ""
    raw: str = ""                       # evidencia bruta (banner, resposta http...)
    data: dict = field(default_factory=dict)


class Collector(Protocol):
    name: str

    async def run(self, targets: list[str], **kwargs) -> list[CollectedFact]:
        ...
