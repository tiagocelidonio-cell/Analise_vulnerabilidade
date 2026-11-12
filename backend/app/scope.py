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

    # Entry como rede/IP (CIDR ou IP exato).
    try:
        entry_net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        entry_net = None

    if entry_net is not None:
        # O alvo pode ser um IP ou um range (CIDR). Dentro do escopo se for
        # sub-rede (ou igual) da rede autorizada. Ex: 10.0.0.0/24 cobre
        # 10.0.0.5 e 10.0.0.0/25.
        try:
            target_net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False  # alvo e hostname, entry e rede -> nao casa
        try:
            return (target_net.version == entry_net.version
                    and target_net.subnet_of(entry_net))
        except (TypeError, ValueError):
            return False

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
