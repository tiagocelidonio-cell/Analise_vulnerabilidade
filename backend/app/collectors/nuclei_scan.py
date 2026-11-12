"""Scanner de vulnerabilidades com nuclei (ProjectDiscovery).

nuclei tem milhares de templates (CVEs, misconfig, exposicoes, etc.). E o que
da profundidade real de analise de vulnerabilidade web. Gera achados com
severidade e CVE ja prontos.

Precisa dos templates (nuclei baixa na 1a execucao ou no build da imagem).
Sem nuclei instalado, retorna vazio (os coletores web proprios continuam).
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import shutil
import tempfile

from app.collectors.base import CollectedFact


def _urls_for(target: str) -> list[str]:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    return [f"http://{t}", f"https://{t}"]


def _parse_line(line: str) -> CollectedFact | None:
    try:
        d = json.loads(line)
    except ValueError:
        return None
    info = d.get("info", {}) or {}
    name = info.get("name") or d.get("template-id", "nuclei")
    severity = (info.get("severity") or "info").lower()
    if severity == "unknown":
        severity = "info"
    matched = d.get("matched-at") or d.get("host") or ""
    host = d.get("host") or matched
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or []
    if isinstance(cves, str):
        cves = [cves]
    cvss = classification.get("cvss-score")
    # alvo "limpo" (host sem esquema)
    tgt = host.replace("https://", "").replace("http://", "").split("/")[0] or matched
    return CollectedFact(
        target=tgt, service="vuln",
        title=f"[nuclei] {name}",
        raw=f"{d.get('template-id', '')}  ->  {matched}",
        data={"severity_hint": severity, "cve_ids": cves,
              "cvss": cvss, "template": d.get("template-id"),
              "matched_at": matched, "source": "nuclei"},
    )


class NucleiCollector:
    name = "web_vuln"

    async def run(self, targets: list[str], **kwargs) -> list[CollectedFact]:
        if not shutil.which("nuclei"):
            return []
        urls: list[str] = []
        for t in targets:
            # ignora ranges (nuclei trabalha com hosts/urls)
            try:
                net = ipaddress.ip_network(t, strict=False)
                if net.num_addresses > 1:
                    continue
            except ValueError:
                pass
            urls += _urls_for(t)
        if not urls:
            return []

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            list_path = f.name

        # Perfil: basico foca no que importa (alto/critico, mais rapido);
        # completo cobre todas as severidades.
        profile = kwargs.get("profile") or "full"
        severity = "high,critical" if profile == "basic" else "low,medium,high,critical"
        args = [
            "nuclei", "-l", list_path, "-silent", "-jsonl",
            "-severity", severity,
            "-rate-limit", "150", "-timeout", "8", "-retries", "1",
            "-disable-update-check",
        ]
        from app.collectors.proc import run_killable
        try:
            out = await run_killable(args, cancel_check=kwargs.get("cancel_check"))
        finally:
            with contextlib.suppress(OSError):
                os.unlink(list_path)
        if not out:  # None (nao iniciou) ou b"" (abortado)
            return []

        facts = []
        for line in out.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            fact = _parse_line(line)
            if fact is not None:
                facts.append(fact)
        return facts
