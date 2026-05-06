"""Testes para seginternet.scanner.ports."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from seginternet.scanner.ports import scan_ports, PortResult


class TestPortResult:
    def test_open_port_returns_open_state(self) -> None:
        """connect_ex retornando 0 deve gerar state='open'."""
        with patch("seginternet.scanner.ports.socket.socket") as mock_socket_cls, \
             patch("seginternet.scanner.ports.socket.getaddrinfo"):
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_socket_cls.return_value = instance

            results = scan_ports("example.com", start=80, end=80, timeout=1.0)

        assert len(results) == 1
        assert results[0].port == 80
        assert results[0].state == "open"

    def test_closed_port_returns_closed_state(self) -> None:
        """connect_ex retornando valor diferente de 0 deve gerar state='closed'."""
        with patch("seginternet.scanner.ports.socket.socket") as mock_socket_cls, \
             patch("seginternet.scanner.ports.socket.getaddrinfo"):
            instance = MagicMock()
            instance.connect_ex.return_value = 111  # Connection refused
            mock_socket_cls.return_value = instance

            results = scan_ports("example.com", start=9999, end=9999, timeout=1.0)

        assert len(results) == 1
        assert results[0].port == 9999
        assert results[0].state == "closed"

    def test_correct_range_of_ports_is_scanned(self) -> None:
        """O número correto de portas deve ser retornado."""
        with patch("seginternet.scanner.ports.socket.socket") as mock_socket_cls, \
             patch("seginternet.scanner.ports.socket.getaddrinfo"):
            instance = MagicMock()
            instance.connect_ex.return_value = 1
            mock_socket_cls.return_value = instance

            results = scan_ports("example.com", start=1, end=10, timeout=0.1)

        assert len(results) == 10
        ports_scanned = sorted(r.port for r in results)
        assert ports_scanned == list(range(1, 11))

    def test_invalid_range_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="inválido"):
            scan_ports("example.com", start=500, end=100)

    def test_unresolvable_host_raises_connection_error(self) -> None:
        import socket as _socket
        with patch(
            "seginternet.scanner.ports.socket.getaddrinfo",
            side_effect=_socket.gaierror("Name or service not known"),
        ):
            with pytest.raises(ConnectionError, match="resolver"):
                scan_ports("host.invalido.xyz", start=80, end=80)

    def test_service_name_populated(self) -> None:
        """Porta 80 deve ter service='http' quando socket.getservbyport funcionar."""
        import socket as _socket

        with patch("seginternet.scanner.ports.socket.socket") as mock_socket_cls, \
             patch("seginternet.scanner.ports.socket.getaddrinfo"), \
             patch(
                 "seginternet.scanner.ports.socket.getservbyport",
                 side_effect=lambda p: "http" if p == 80 else (_ for _ in ()).throw(OSError()),
             ):
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_socket_cls.return_value = instance

            results = scan_ports("example.com", start=80, end=80)

        assert results[0].service == "http"

    def test_unknown_service_fallback(self) -> None:
        """Porta sem serviço conhecido deve retornar service='unknown'."""
        with patch("seginternet.scanner.ports.socket.socket") as mock_socket_cls, \
             patch("seginternet.scanner.ports.socket.getaddrinfo"), \
             patch(
                 "seginternet.scanner.ports.socket.getservbyport",
                 side_effect=OSError,
             ):
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_socket_cls.return_value = instance

            results = scan_ports("example.com", start=39999, end=39999)

        assert results[0].service == "unknown"
