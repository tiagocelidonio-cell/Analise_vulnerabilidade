"""Expansao de alvos: transforma ranges (CIDR) em IPs individuais.

O scanner e TCP connect (acha host com porta aberta mesmo sem responder a
ping). Para varrer uma rede, expandimos o CIDR nos IPs e escaneamos cada um.
Dominios e IPs isolados passam inalterados.
"""
from __future__ import annotations

import ipaddress

MAX_HOSTS = 8192  # teto de seguranca (evita varrer /16 inteiro de uma vez)


def expand_targets(targets: list[str], max_hosts: int = MAX_HOSTS) -> list[str]:
    """Expande CIDRs em IPs; mantem dominios/IPs. Erra se passar do teto."""
    out: list[str] = []
    for raw in targets:
        t = (raw or "").strip()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            out.append(t)  # dominio/hostname
            continue
        if net.num_addresses == 1:
            out.append(str(net.network_address))
            continue
        hosts = net.hosts() if net.prefixlen < net.max_prefixlen else [net.network_address]
        for ip in hosts:
            out.append(str(ip))
            if len(out) > max_hosts:
                raise ValueError(
                    f"Range muito grande (>{max_hosts} hosts). "
                    f"Divida em sub-redes menores (ex: /24)."
                )
    # remove duplicatas preservando a ordem
    seen: set[str] = set()
    uniq = []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def host_count(targets: list[str], max_hosts: int = MAX_HOSTS) -> int:
    """Conta quantos hosts a varredura geraria (valida tamanho antes de rodar)."""
    return len(expand_targets(targets, max_hosts))
