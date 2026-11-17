"""Executa um subprocesso que pode ser MORTO no meio quando o scan e
cancelado/pausado. Isso e o que faz o 'Parar' interromper de verdade o nmap/
nuclei (antes eles rodavam ate o fim do lote antes de checar cancelamento).

cancel_check: coroutine opcional que retorna verdadeiro quando o scan deve
parar. E consultada a cada `poll` segundos enquanto o processo roda.
"""
from __future__ import annotations

import asyncio
import contextlib


async def run_killable(
    args: list[str],
    cancel_check=None,
    poll: float = 1.0,
    on_tick=None,
    max_seconds: float | None = None,
    on_log=None,
) -> bytes | None:
    """Roda `args`, devolvendo o stdout em bytes.

    - Retorna None se nem conseguiu iniciar (ex.: binario ausente) -> fallback.
    - Retorna b"" se foi abortado por cancel_check (mata o processo).
    - on_tick: coroutine opcional chamada a cada poll enquanto roda (heartbeat).
    - max_seconds: TETO de parede. Se o processo passar disso, e morto (evita
      um binario travado — ex.: chromium numa pagina ruim — pendurar o scan).
    """
    if on_log is not None:
        try:
            on_log("$ " + " ".join(str(a) for a in args))
        except Exception:  # noqa: BLE001
            pass
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        if on_log is not None:
            try:
                on_log(f"[erro] não foi possível iniciar: {args[0]}", "error")
            except Exception:  # noqa: BLE001
                pass
        return None

    loop = asyncio.get_event_loop()
    started = loop.time()
    comm = asyncio.ensure_future(proc.communicate())
    while not comm.done():
        done, _ = await asyncio.wait({comm}, timeout=poll)
        if comm in done:
            break
        if on_tick is not None:
            try:
                await on_tick()
            except Exception:  # noqa: BLE001  batimento nunca derruba o scan
                pass
        timed_out = max_seconds is not None and (loop.time() - started) > max_seconds
        if timed_out:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(comm, 5)
            except Exception:  # noqa: BLE001  nao morreu -> kill
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await asyncio.gather(comm, return_exceptions=True)
            return b""
        if cancel_check is not None:
            try:
                stop = bool(await cancel_check())
            except Exception:  # noqa: BLE001  nunca derruba o scan por isso
                stop = False
            if stop:
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
                try:
                    await asyncio.wait_for(comm, 5)
                except Exception:  # noqa: BLE001  nao morreu em 5s -> kill
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    await asyncio.gather(comm, return_exceptions=True)
                return b""
    try:
        out, _ = comm.result()
    except Exception:  # noqa: BLE001
        return None
    return out
