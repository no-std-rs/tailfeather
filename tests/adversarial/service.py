#!/usr/bin/env python3
"""Deterministic repo-only fault server for the physical-device suite."""

import argparse
import asyncio
import json
import pathlib
import ssl
import struct
import subprocess
import tempfile


def map33() -> bytes:
    peers = []
    for index in range(1, 34):
        peers.append({
            "ID": index,
            "Key": "nodekey:" + (bytes([index]) * 32).hex(),
            "DiscoKey": "discokey:" + (bytes([index ^ 0x80]) * 32).hex(),
            "Online": True,
            "HomeDERP": 999,
            "Addresses": [f"100.64.0.{index}/32"],
            "AllowedIPs": [f"100.64.0.{index}/32"],
            "Endpoints": [f"192.0.2.{index}:41641"],
        })
    body = json.dumps({"Peers": peers}, separators=(",", ":")).encode()
    return struct.pack("<I", len(body)) + body


PAYLOADS = {
    "map33": map33,
    "malformed-noise": lambda: b"HTTP/1.1 101 Switching Protocols\r\n\r\n\x03\xff\xff",
    "malformed-h2": lambda: b"\x00\x40\x01\x00\x00\x00\x00\x00\x01",
    "malformed-control": lambda: struct.pack("<I", 9) + b'{"Peers":',
    "malformed-derp": lambda: b"\x01\x00\x00\x00\x28NOT-DERP",
}


async def serve_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, args) -> None:
    try:
        await asyncio.wait_for(reader.read(4096), timeout=5)
    except (TimeoutError, asyncio.TimeoutError):
        pass
    payload = PAYLOADS.get(args.mode, lambda: b"synthetic disconnect boundary")()
    if args.mode == "disconnect":
        payload = payload[: args.cut]
    writer.write(payload)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


def tls_context(directory: pathlib.Path) -> ssl.SSLContext:
    key = directory / "key.pem"
    certificate = directory / "certificate.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
        "-subj", "/CN=wrong.invalid", "-keyout", str(key), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    return context


async def main(args) -> None:
    with tempfile.TemporaryDirectory(prefix="tailfeather-adversarial-") as temporary:
        context = tls_context(pathlib.Path(temporary)) if args.mode == "tls-wrong-name" else None
        server = await asyncio.start_server(
            lambda reader, writer: serve_client(reader, writer, args),
            args.host,
            args.port,
            ssl=context,
        )
        addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        print(f"synthetic adversarial mode={args.mode} listening on {addresses}", flush=True)
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--mode", choices=[*PAYLOADS, "disconnect", "tls-wrong-name"], required=True)
    parser.add_argument("--cut", type=int, default=7)
    asyncio.run(main(parser.parse_args()))
