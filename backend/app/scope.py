"""Gate de autorizacao e escopo.

Regra de ouro do produto: nenhum alvo e tocado sem estar no escopo
autorizado de um Engagement. Isto separa ferramenta de seguranca de
ferramenta de abuso.
"""
from __future__ import annotations

import ipaddress


def _matches_entry(target: str, entry: str) -> bool:
    entry = entry.strip().lower()
    target = target.strip().lower()
    if not entry:
        return False

    # Tenta casar como rede/IP (CIDR ou IP exato).
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(target) in net
        except ValueError:
            return False  # target e hostname, entry e rede -> nao casa
    except ValueError:
        pass

    # Casamento de dominio: "example.com" cobre "example.com" e subdominios.
    if target == entry:
        return True
    if target.endswith("." + entry):
        return True
    return False


def is_in_scope(target: str, scope: list[str]) -> bool:
    return any(_matches_entry(target, entry) for entry in scope)


def validate_targets(targets: list[str], scope: list[str]) -> list[str]:
    """Retorna os alvos FORA do escopo. Lista vazia = tudo liberado."""
    return [t for t in targets if not is_in_scope(t, scope)]
