#!/usr/bin/env python3
"""A hardened SOCKS5 CONNECT server that speaks the mutated wire format.

Normal SOCKS5                     This server on the wire
--------------------------------  ---------------------------------
client  05 NN methods...          client  16 NN methods...
server  05 00                     server  16 00
client  05 01 00 ATYP ...         client  16 01 00 ATYP ...
server  05 REP 00 ATYP ...        server  16 REP 00 ATYP ...

The companion tc/eBPF program on the router performs the same translation for
unmodified SOCKS5 clients.  CONNECT only; there is no SOCKS authentication.

Safety model:
  * Optional source allowlist.  Without --allow/--allow-file every source is
    accepted; use a firewall if the service is public.  With either option,
    non-listed peers are reset before any SOCKS parsing.
  * Invalid, truncated or slow handshakes are reset with TCP RST and count
    toward a temporary per-IP ban.
  * Per-IP concurrency and connection-rate limits.
  * The listener stays up during probes; killing it on a probe would let any
    scanner take the service down.

Exit codes: 0 clean shutdown, 1 fatal error.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import logging
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
from typing import Union

MUT_VER = 0x16
PLAIN_VER = 0x05
CMD_CONNECT = 0x01
MAX_METHODS = 8

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


class ProbeError(Exception):
    pass


def reset_close(sock: socket.socket) -> None:
    """Close with SO_LINGER=0 so the peer gets a TCP RST, not a clean FIN."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
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
        if length == 0:
            raise ValueError("empty domain")
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
    if isinstance(exc, OSError):
        if exc.errno == errno.ENETUNREACH:
            return REP_NETWORK_UNREACHABLE
        if exc.errno == errno.EHOSTUNREACH:
            return REP_HOST_UNREACHABLE
    return REP_GENERAL


def normalize_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    addr = ipaddress.ip_address(text.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_network(token: str, source: str) -> Network:
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        raise ValueError(f"{source}: invalid CIDR {token!r}: {exc}") from exc


class AllowList:
    """CLI entries plus an optional file reloaded on SIGHUP."""

    def __init__(self, cli_entries: list[str], path: str | None) -> None:
        self.path = path
        self.enabled = bool(cli_entries or path)
        self.lock = threading.Lock()
        self.cli = self._parse(cli_entries, "command line")
        self.file: list[Network] = []
        if path:
            self.file = self._read_file(path)

    @staticmethod
    def _parse(entries: list[str], source: str) -> list[Network]:
        nets: list[Network] = []
        for entry in entries:
            for token in entry.replace(",", " ").split():
                nets.append(parse_network(token, source))
        return nets

    def _read_file(self, path: str) -> list[Network]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = [line.split("#", 1)[0] for line in handle]
        except OSError as exc:
            raise ValueError(f"cannot read allowlist {path}: {exc}") from exc
        return self._parse(lines, path)

    def reload(self) -> None:
        if not self.path:
            return
        try:
            nets = self._read_file(self.path)
        except ValueError as exc:
            # Keep the old list on a bad reload.  Never fail open.
            LOG.error("allowlist reload failed: %s", exc)
            return
        with self.lock:
            self.file = nets
        if nets:
            LOG.info("allowlist reloaded: %d file entries", len(nets))
        else:
            LOG.warning("allowlist reloaded but empty; denying all new connections")

    def contains(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if not self.enabled:
            return True
        with self.lock:
            nets = self.cli + self.file
        return any(addr.version == net.version and addr in net for net in nets)

    def empty(self) -> bool:
        with self.lock:
            return not self.cli and not self.file

    def count(self) -> int:
        with self.lock:
            return len(self.cli) + len(self.file)


class Guard:
    """Per-IP admission, rate limiting and temporary bans."""

    def __init__(
        self,
        allow: AllowList,
        max_per_ip: int,
        rate: int,
        rate_window: float,
        ban_after: int,
        ban_time: float,
    ) -> None:
        self.allow = allow
        self.max_per_ip = max_per_ip
        self.rate = rate
        self.rate_window = rate_window
        self.ban_after = ban_after
        self.ban_time = ban_time
        self.lock = threading.Lock()
        self.active: dict[str, int] = {}
        self.hits: dict[str, deque[float]] = {}
        self.fails: dict[str, int] = {}
        self.banned: dict[str, float] = {}
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def admit(self, ip: str) -> tuple[bool, str]:
        if not self.allow.contains(ipaddress.ip_address(ip)):
            return False, "not allowlisted"

        now = time.monotonic()
        with self.lock:
            until = self.banned.get(ip)
            if until is not None:
                if until > now:
                    return False, "temporarily banned"
                self.banned.pop(ip, None)

            if self.max_per_ip > 0 and self.active.get(ip, 0) >= self.max_per_ip:
                return False, "per-ip concurrency"

            if self.rate > 0:
                hits = self.hits.setdefault(ip, deque())
                while hits and now - hits[0] > self.rate_window:
                    hits.popleft()
                if len(hits) >= self.rate:
                    return False, "per-ip rate"
                hits.append(now)

            self.active[ip] = self.active.get(ip, 0) + 1
            return True, ""

    def close(self, ip: str) -> None:
        with self.lock:
            active = self.active.get(ip, 0) - 1
            if active > 0:
                self.active[ip] = active
            else:
                self.active.pop(ip, None)

    def fail(self, ip: str) -> None:
        if self.ban_after <= 0:
            return
        with self.lock:
            fails = self.fails.get(ip, 0) + 1
            if fails >= self.ban_after:
                self.fails.pop(ip, None)
                self.banned[ip] = time.monotonic() + self.ban_time
                LOG.warning(
                    "temporarily banning %s for %.0fs after %d bad handshakes",
                    ip,
                    self.ban_time,
                    fails,
                )
            else:
                self.fails[ip] = fails

    def success(self, ip: str) -> None:
        with self.lock:
            self.fails.pop(ip, None)

    def _cleanup_loop(self) -> None:
        interval = max(30.0, min(300.0, self.rate_window))
        while True:
            time.sleep(interval)
            now = time.monotonic()
            with self.lock:
                for ip, until in list(self.banned.items()):
                    if until <= now:
                        self.banned.pop(ip, None)
                for ip, hits in list(self.hits.items()):
                    while hits and now - hits[0] > self.rate_window:
                        hits.popleft()
                    if not hits:
                        self.hits.pop(ip, None)
                for ip, count in list(self.active.items()):
                    if count <= 0:
                        self.active.pop(ip, None)


def handle_client(
    client: socket.socket,
    peer: tuple,
    allow_plain: bool,
    handshake_timeout: float,
    guard: Guard,
) -> None:
    ip = str(normalize_ip(peer[0]))
    hard_close = True
    try:
        client.settimeout(handshake_timeout)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        first = recv_exact(client, 2)
        if first[0] == MUT_VER or (first[0] == PLAIN_VER and allow_plain):
            version = first[0]
            mutated = version == MUT_VER
            nmethods = first[1]
            if nmethods == 0 or nmethods > MAX_METHODS:
                raise ProbeError("bad method count")

            methods = recv_exact(client, nmethods)
            # We only implement no-auth.  Requiring it first also filters
            # most TLS/HTTP probes, which start with 16 03 01 ...
            if methods[0] != 0x00:
                raise ProbeError("no no-auth method")

            client.sendall(bytes((version, 0x00)))
        else:
            raise ProbeError("bad version")

        expected_ver = MUT_VER if mutated else PLAIN_VER
        header = recv_exact(client, 4)
        if (
            header[0] != expected_ver
            or header[1] != CMD_CONNECT
            or header[2] != 0x00
        ):
            raise ProbeError("bad request")
        if header[3] not in (0x01, 0x03, 0x04):
            raise ProbeError("bad ATYP")

        try:
            host, port = read_target(client, header[3])
        except ValueError as exc:
            raise ProbeError("bad target") from exc

        guard.success(ip)
        hard_close = False
        if LOG.isEnabledFor(logging.INFO):
            LOG.info("%s -> %s:%d", ip, host, port)

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            LOG.warning("%s: connect %s:%d failed: %s", ip, host, port, exc)
            send_reply(client, expected_ver, map_connect_error(exc))
            return

        with upstream:
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream.settimeout(None)
            client.settimeout(None)
            family, addr, bport = bound_address(upstream)
            send_reply(client, expected_ver, REP_SUCCESS, family, addr, bport)
            relay(client, upstream)
    except (ShortRead, ProbeError, TimeoutError, socket.timeout) as exc:
        guard.fail(ip)
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("probe from %s: %s", ip, exc or "short read")
    except OSError as exc:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("%s: %s", ip, exc)
    finally:
        if hard_close:
            reset_close(client)
        else:
            close_quietly(client)


def serve(args: argparse.Namespace) -> int:
    family = socket.AF_INET6 if ":" in args.bind else socket.AF_INET
    allow = AllowList(list(args.allow), args.allow_file)
    if not allow.enabled:
        LOG.warning("source allowlist disabled; all peers may use the proxy")
    elif allow.empty():
        LOG.warning("allowlist is empty; all peers will be denied")

    guard = Guard(
        allow,
        args.max_per_ip,
        args.rate,
        args.rate_window,
        args.ban_after,
        args.ban_time,
    )

    listener = socket.socket(family)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(args.backlog)
    if allow.enabled:
        LOG.info(
            "mutated SOCKS5 listening on %s:%d (allowlist entries: %d)",
            args.bind,
            args.port,
            allow.count(),
        )
    else:
        LOG.warning(
            "mutated SOCKS5 listening on %s:%d (source allowlist disabled)",
            args.bind,
            args.port,
        )

    slots = threading.BoundedSemaphore(args.max_conns)
    stop = threading.Event()

    def on_signal(_signum: int, _frame: object) -> None:
        stop.set()
        listener.close()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda _s, _f: allow.reload())

    while not stop.is_set():
        try:
            client, peer = listener.accept()
        except OSError:
            if stop.is_set():
                break
            raise

        try:
            ip = str(normalize_ip(peer[0]))
        except ValueError:
            reset_close(client)
            continue

        if not slots.acquire(blocking=False):
            LOG.warning("global connection limit, dropping %s", ip)
            reset_close(client)
            continue

        allowed, reason = guard.admit(ip)
        if not allowed:
            slots.release()
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("denied %s: %s", ip, reason)
            reset_close(client)
            continue

        def run(c: socket.socket = client, p: tuple = peer, addr: str = ip) -> None:
            try:
                handle_client(c, p, args.allow_plain, args.handshake_timeout, guard)
            except Exception:  # noqa: BLE001 - last-resort thread guard
                LOG.exception("unhandled error for %s", addr)
            finally:
                guard.close(addr)
                slots.release()

        threading.Thread(target=run, daemon=True).start()

    LOG.info("shutting down")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hardened mutated SOCKS5 server")
    parser.add_argument("--bind", default="0.0.0.0", help="listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=1080, help="listen port (default: 1080)")
    parser.add_argument("--backlog", type=int, default=128)
    parser.add_argument("--max-conns", type=int, default=256)
    parser.add_argument("--max-per-ip", type=int, default=8, help="concurrent connections per IP (0 = unlimited)")
    parser.add_argument("--rate", type=int, default=60, help="new connections per IP per window (0 = unlimited)")
    parser.add_argument("--rate-window", type=float, default=60.0, help="rate window in seconds")
    parser.add_argument("--ban-after", type=int, default=3, help="bad handshakes before a temporary ban (0 = disable)")
    parser.add_argument("--ban-time", type=float, default=300.0, help="ban duration in seconds")
    parser.add_argument("--handshake-timeout", type=float, default=3.0, help="seconds to finish the SOCKS handshake")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="CIDR",
        help="optional source allowlist CIDR (repeatable or comma-separated)",
    )
    parser.add_argument(
        "--allow-file",
        metavar="PATH",
        help="optional allowlist file, one CIDR per line; SIGHUP reloads it",
    )
    parser.add_argument(
        "--allow-plain",
        action="store_true",
        help="also accept normal SOCKS5 (debugging only)",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)

    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be 1..65535")
    if args.backlog < 1:
        parser.error("--backlog must be >= 1")
    if args.max_conns < 1:
        parser.error("--max-conns must be >= 1")
    if args.max_per_ip < 0:
        parser.error("--max-per-ip must be >= 0")
    if args.rate < 0:
        parser.error("--rate must be >= 0")
    if args.rate_window <= 0:
        parser.error("--rate-window must be > 0")
    if args.ban_after < 0:
        parser.error("--ban-after must be >= 0")
    if args.ban_time < 0:
        parser.error("--ban-time must be >= 0")
    if args.handshake_timeout <= 0:
        parser.error("--handshake-timeout must be > 0")
    return args


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
    except (OSError, ValueError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
