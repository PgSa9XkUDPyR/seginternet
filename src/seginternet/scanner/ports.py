"""Scanner de portas TCP com execução paralela."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed"
    service: str


def _probe_port(host: str, port: int, timeout: float) -> PortResult:
    service = _service_name(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    sock.close()
    state = "open" if result == 0 else "closed"
    return PortResult(port=port, state=state, service=service)


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def scan_ports(
    host: str,
    start: int = 1,
    end: int = 1024,
    timeout: float = 1.0,
) -> list[PortResult]:
    """Escaneia portas TCP de *start* a *end* (inclusive) em *host*.

    Levanta ValueError se o intervalo de portas for inválido.
    Levanta ConnectionError se o host não puder ser resolvido.
    """
    if start < 1 or end > 65535 or start > end:
        raise ValueError(
            f"Intervalo de portas inválido: {start}-{end}. Use 1-65535."
        )

    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ConnectionError(
            f"Não foi possível resolver o host '{host}': {exc}"
        ) from exc

    ports = range(start, end + 1)
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=min(100, len(ports))) as pool:
        futures = {pool.submit(_probe_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.port)
    return results
