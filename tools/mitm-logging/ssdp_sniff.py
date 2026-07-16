#!/usr/bin/env python3
"""Passive SSDP sniffer for Bambu printer NOTIFY broadcasts.

Bambu printers advertise themselves on the LAN by broadcasting an SSDP-style
NOTIFY (to 239.255.255.250:2021, some models also :1900) every few seconds. The
genuine plugin's discovery is a receive-only UDP listener -- no TLS, no proxy --
so this sniffer captures the exact wire the plugin would parse.

Each captured NOTIFY is appended to the log as one NDJSON line:

    {"proto":"ssdp","transport":"udp:2021","src":"192.168.1.116","packet":"NOTIFY * HTTP/1.1\r\n..."}

Feed the log to import_flow.py --flow ssdp_discovery to get an anonymized
ssdp_discovery fixture. Runs standalone; no printer credentials needed.

Usage: ssdp_sniff.py [--port 2021] [--seconds 20] [--out LOG.jsonl] [--count N]
"""
import argparse
import json
import socket
import struct
import sys
import time

MCAST = "239.255.255.250"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2021)
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0=until timeout)")
    ap.add_argument("--out", default="ssdp.jsonl")
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    s.bind(("", args.port))
    # join the canonical SSDP multicast group (some models advertise there).
    try:
        mreq = struct.pack("4sl", socket.inet_aton(MCAST), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError as e:
        sys.stderr.write(f"[ssdp] multicast join failed (unicast still works): {e}\n")
    s.settimeout(1.0)

    fh = open(args.out, "a", buffering=1)
    seen_src = set()
    n = 0
    deadline = time.time() + args.seconds
    sys.stderr.write(f"[ssdp] listening on udp/{args.port} for {args.seconds:g}s...\n")
    while time.time() < deadline:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        text = data.decode("utf-8", "replace")
        if not text.upper().startswith("NOTIFY"):
            continue
        rec = {"proto": "ssdp", "transport": f"udp:{args.port}",
               "src": addr[0], "packet": text}
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        n += 1
        if addr[0] not in seen_src:
            seen_src.add(addr[0])
            sys.stderr.write(f"[ssdp] NOTIFY from {addr[0]} ({len(text)} bytes)\n")
        if args.count and n >= args.count:
            break
    fh.close()
    sys.stderr.write(f"[ssdp] captured {n} NOTIFY packet(s) from {len(seen_src)} host(s) -> {args.out}\n")
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
