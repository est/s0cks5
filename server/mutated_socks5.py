#!/usr/bin/env python3
"""A SOCKS5 CONNECT server that speaks the mutated wire format.

Normal SOCKS5                     This server on the wire
--------------------------------  ---------------------------------
client  05 NN methods...          client  16 NN methods...
server  05 00                     server  16 00
client  05 01 00 ATYP ...         client  16 01 00 ATYP ...
server  05 REP 00 ATYP ...        server  16 REP 00 ATYP ...

The companion tc/eBPF program on the router performs the same translation for
unmodified SOCKS5 clients.  CONNECT only; no authentication.

Exit codes: 0 clean shutdown, 1 fatal error.
"""

from __future__ import annotations

import argparse
import errno
import logging
import signal
import socket
import struct
import sys
import threading

MUT_VER = 0x16
PLAIN_VER = 0x05
CMD_CONNECT = 0x01

REP_SUCCESS = 0x00
REP_GENERAL = 0x01
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

LOG = logging.getLogger("s0cks5")


class ShortRead(Exception):
    pass


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ShortRead
        buf.extend(chunk)
    return bytes(buf)


def send_reply(
    sock: socket.socket,
    version: int,
    rep: int,
    atyp: int = 0x01,
    addr: bytes = b"\x00\x00\x00\x00",
    port: int = 0,
) -> None:
    sock.sendall(bytes((version, rep, 0x00, atyp)) + addr + struct.pack("!H", port))


def read_target(sock: socket.socket, atyp: int) -> tuple[str, int]:
    if atyp == 0x01:
        raw = recv_exact(sock, 4)
        host = socket.inet_ntoa(raw)
    elif atyp == 0x03:
        length = recv_exact(sock, 1)[0]
        host = recv_exact(sock, length).decode("idna")
    elif atyp == 0x04:
        raw = recv_exact(sock, 16)
        host = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        raise ValueError(f"unsupported ATYP 0x{atyp:02x}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return host, port


def bound_address(sock: socket.socket) -> tuple[int, bytes, int]:
    address = sock.getsockname()
    if sock.family == socket.AF_INET6:
        return 0x04, socket.inet_pton(socket.AF_INET6, address[0]), address[1]
    return 0x01, socket.inet_aton(address[0]), address[1]


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay(client: socket.socket, upstream: socket.socket) -> None:
    a = threading.Thread(target=pump, args=(client, upstream), daemon=True)
    b = threading.Thread(target=pump, args=(upstream, client), daemon=True)
    a.start()
    b.start()
    a.join()
    b.join()


def map_connect_error(exc: BaseException) -> int:
    if isinstance(exc, ConnectionRefusedError):
        return REP_CONNECTION_REFUSED
    if isinstance(exc, socket.gaierror):
        return REP_HOST_UNREACHABLE
    if isinstance(exc, TimeoutError):
        return REP_HOST_UNREACHABLE
    if isinstance(exc, OSError) and exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return REP_NETWORK_UNREACHABLE
    return REP_GENERAL


def handle_client(client: socket.socket, peer: tuple, allow_plain: bool) -> None:
    try:
        client.settimeout(30)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        first = recv_exact(client, 2)
        if first[0] == MUT_VER or (first[0] == PLAIN_VER and allow_plain):
            mutated = first[0] == MUT_VER
            methods = recv_exact(client, first[1]) if first[1] else b""
            if 0x00 not in methods:
                client.sendall(bytes((first[0], 0xFF)))
                return
            client.sendall(bytes((first[0], 0x00)))
        else:
            LOG.warning("%s: not a mutated SOCKS5 greeting: %s", peer[0], first.hex())
            return

        expected_ver = MUT_VER if mutated else PLAIN_VER
        header = recv_exact(client, 4)
        if header[0] != expected_ver or header[2] != 0x00:
            LOG.warning("%s: bad request header: %s", peer[0], header.hex())
            return
        if header[1] != CMD_CONNECT:
            send_reply(client, expected_ver, REP_CMD_NOT_SUPPORTED)
            return

        atyp = header[3]
        try:
            host, port = read_target(client, atyp)
        except ValueError:
            send_reply(client, MUT_VER if mutated else PLAIN_VER, REP_ATYP_NOT_SUPPORTED)
            return

        if LOG.isEnabledFor(logging.INFO):
            LOG.info("%s -> %s:%d", peer[0], host, port)

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except BaseException as exc:  # noqa: BLE001 - turned into a SOCKS reply
            LOG.warning("%s: connect %s:%d failed: %s", peer[0], host, port, exc)
            send_reply(client, MUT_VER if mutated else PLAIN_VER, map_connect_error(exc))
            return

        with upstream:
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream.settimeout(None)
            client.settimeout(None)
            family, addr, bport = bound_address(upstream)
            send_reply(client, MUT_VER if mutated else PLAIN_VER, REP_SUCCESS, family, addr, bport)
            relay(client, upstream)
    except ShortRead:
        pass
    except OSError as exc:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("%s: %s", peer[0], exc)
    finally:
        try:
            client.close()
        except OSError:
            pass


def serve(args: argparse.Namespace) -> int:
    listener = socket.socket(socket.AF_INET6 if ":" in args.bind else socket.AF_INET)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(args.backlog)
    LOG.info("mutated SOCKS5 listening on %s:%d", args.bind, args.port)

    slots = threading.BoundedSemaphore(args.max_conns)
    stop = threading.Event()

    def on_signal(_signum: int, _frame: object) -> None:
        stop.set()
        listener.close()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    while not stop.is_set():
        try:
            client, peer = listener.accept()
        except OSError:
            if stop.is_set():
                break
            raise

        if not slots.acquire(blocking=False):
            LOG.warning("connection limit reached, dropping %s", peer[0])
            client.close()
            continue

        def run(c: socket.socket = client, p: tuple = peer) -> None:
            try:
                handle_client(c, p, args.allow_plain)
            finally:
                slots.release()

        threading.Thread(target=run, daemon=True).start()

    LOG.info("shutting down")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mutated SOCKS5 CONNECT server")
    parser.add_argument("--bind", default="0.0.0.0", help="listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=1080, help="listen port (default: 1080)")
    parser.add_argument("--backlog", type=int, default=128)
    parser.add_argument("--max-conns", type=int, default=256)
    parser.add_argument(
        "--allow-plain",
        action="store_true",
        help="also accept normal SOCKS5 (debugging only)",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")
    try:
        return serve(args)
    except OSError as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
