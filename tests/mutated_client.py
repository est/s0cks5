#!/usr/bin/env python3
"""Tiny client for the mutated SOCKS5 server (direct connection test).

This intentionally speaks the mutated wire format itself, so it must talk
straight to the server; run it through the router and the router's eBPF
program would restore the server replies to normal SOCKS5.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise SystemExit("unexpected EOF")
        buf.extend(chunk)
    return bytes(buf)


def address_field(host: str) -> tuple[int, bytes]:
    try:
        return 0x01, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 0x04, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        raw = host.encode("idna")
        return 0x03, bytes((len(raw),)) + raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True, help="mutated SOCKS5 server host")
    parser.add_argument("--proxy-port", type=int, default=1080)
    parser.add_argument("--target", required=True, help="destination host")
    parser.add_argument("--target-port", type=int, default=80)
    parser.add_argument(
        "--request",
        default="GET / HTTP/1.0\r\n\r\n",
        help="raw bytes to send after CONNECT",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    with socket.create_connection((args.proxy, args.proxy_port), timeout=args.timeout) as sock:
        sock.sendall(bytes((0x16, 0x01, 0x00)))
        greeting_reply = recv_exact(sock, 2)
        if greeting_reply != bytes((0x16, 0x00)):
            print(f"bad greeting reply: {greeting_reply.hex()}", file=sys.stderr)
            return 1

        atyp, addr = address_field(args.target)
        sock.sendall(
            bytes((0x16, 0x01, 0x00, atyp))
            + addr
            + struct.pack("!H", args.target_port)
        )
        reply = recv_exact(sock, 4)
        if reply[0] != 0x16 or reply[1] != 0x00:
            print(f"CONNECT failed: {reply.hex()}", file=sys.stderr)
            return 1

        reply_atyp = reply[3]
        if reply_atyp == 0x01:
            recv_exact(sock, 4 + 2)
        elif reply_atyp == 0x04:
            recv_exact(sock, 16 + 2)
        elif reply_atyp == 0x03:
            length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
        else:
            print(f"bad reply ATYP: {reply_atyp}", file=sys.stderr)
            return 1

        sock.sendall(args.request.encode())
        while True:
            data = sock.recv(65536)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
