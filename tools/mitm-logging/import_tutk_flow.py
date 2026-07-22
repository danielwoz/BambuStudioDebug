#!/usr/bin/env python3
"""Turn a genuine TUTK camera capture into an OBN wire-compliance fixture.

Reads a `socklog.txt` (from socklog/socklog.so) or a pcap, isolates the TUTK
UDP session, deobfuscates every datagram with tutk_decode, and emits an
`obn-wire-flow/v1` fixture (meta / identity_block / vars / steps) matching the
schema in OBN's tests/wire-fixtures. Each step is one wire event: direction,
peer, message kind, and the decoded IOTC/DTLS fields.

Every session-specific secret is redacted before writing — cloud UID, session
tokens, p2p nonce, reflexive/candidate addresses, authkey and DTLS randoms are
replaced with fixed placeholders; the printer IP becomes 192.168.1.2 and public
addresses become TEST-NET (203.0.113.x). The output is a pure log of the wire
shape and carries no live values.

    import_tutk_flow.py socklog.txt -o flow.json [--model h2s] [--version 02.07.00.50]
"""
import argparse
import ipaddress
import json
import sys

import tutk_decode as T

# Fixed anonymization placeholders (format-preserving, obviously synthetic).
UID_PLACEHOLDER = "TUTKUID0000000000000"   # 20-char uppercase, like a real UID
TOKEN_PLACEHOLDER = "0000000000000000"     # 8-byte session token (hex)
NONCE_PLACEHOLDER = "0000000000000000"     # 16-byte ASCII p2p nonce
PRINTER_IP = "192.168.1.2"                 # matches other fixtures' anonymized LAN IP


class Anonymizer:
    """Maps captured addresses to deterministic placeholders."""

    def __init__(self):
        self._public = {}      # real public ip -> 203.0.113.N
        self._next = 1
        self.printer_ip = None

    def note_printer(self, ip):
        self.printer_ip = ip

    def ip(self, ip):
        if ip == self.printer_ip:
            return PRINTER_IP
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if addr.is_private or addr.is_multicast or addr.is_loopback:
            return ip if not addr.is_private else PRINTER_IP
        if ip not in self._public:
            self._public[ip] = "203.0.113.%d" % self._next
            self._next += 1
        return self._public[ip]

    def peer(self, peer):
        if not peer or ":" not in peer:
            return peer
        host, _, port = peer.rpartition(":")
        return "%s:%s" % (self.ip(host), port)

    def addr(self, hostport):
        return self.peer(hostport) if hostport else hostport


def _dir(call):
    return "c2p" if call in ("sendto", "send", "sendmsg") else "p2c"


def _iotc_meta(plain):
    return {
        "magic": plain[0:2].hex(),
        "version": "%02x" % plain[2],
        "flags": "%02x" % plain[3],
        "msgtype": plain[8:11].hex(),
    }


def _anon_fields(kind, info, anon):
    """Return the redacted, decoded fields for a step (no secrets)."""
    f = {}
    if kind in ("lan_search3",):
        f = {
            "uid": UID_PLACEHOLDER,
            "iotc_version": info.get("iotc_version"),
            "client_random": "0xREDACTED",
            "partial_mac": "0xREDACTED",
            "search_type": info.get("search_type"),
        }
    elif kind == "ctrl_0x33":
        f = {"uid": UID_PLACEHOLDER, "session_token": TOKEN_PLACEHOLDER, "tag": info.get("tag")}
    elif kind == "master_lookup_req":
        f = {"uid": UID_PLACEHOLDER, "nonce": NONCE_PLACEHOLDER}
    elif kind == "master_lookup_reply":
        f = {
            "uid": UID_PLACEHOLDER,
            "reflexive": anon.addr(info.get("reflexive")),
            "candidates": [anon.addr(c) for c in info.get("candidates", [])],
        }
    elif kind in ("dtls_c2p", "dtls_p2c"):
        f = {"session_token": TOKEN_PLACEHOLDER}
        for k in ("record_type", "dtls_version", "epoch", "record_len", "handshake_type"):
            if k in info:
                f[k] = info[k]
        if info.get("handshake_type") == "client_hello":
            f["cipher_suites"] = info.get("cipher_suites", [])
            f["extensions"] = info.get("extensions", [])
    return f


def build_fixture(datagrams, model, version):
    anon = Anonymizer()
    # Identify the printer: the private-LAN peer of the DTLS session port.
    for _ts, call, _fd, peer, raw in datagrams:
        info = T.parse_packet(raw)
        if info["kind"] in ("dtls_c2p", "dtls_p2c") and ":" in peer:
            host = peer.rsplit(":", 1)[0]
            try:
                if ipaddress.ip_address(host).is_private:
                    anon.note_printer(host)
                    break
            except ValueError:
                pass

    steps = []
    seq = 0

    # Walk the session, coalescing the broadcast fan-out and the AV stream.
    # Everything up to the DTLS handshake is emitted event-by-event; once the
    # channel reaches steady state (encrypted ApplicationData), the flood in each
    # direction collapses into one repeatable stream step with an observed count.
    pending_bcast = None   # collect broadcast lan_search peers
    stream = {}            # dir -> {count, peer, iotc, epoch}

    def flush_bcast():
        nonlocal pending_bcast, seq
        if not pending_bcast:
            return
        seq += 1
        ports = sorted({p.rsplit(":", 1)[1] for p in pending_bcast["peers"]})
        steps.append({
            "seq": seq, "id": "lan_search3_broadcast", "protocol": "tutk",
            "channel_only": "lan", "repeatable": True,
            "request": {
                "transport": "udp", "dir": "c2p",
                "peer": "255.255.255.255:{%s}" % ",".join(ports),
                "op": "lan_search3", "iotc": pending_bcast["iotc"],
                "fields": pending_bcast["fields"],
            },
        })
        pending_bcast = None

    def flush_stream():
        nonlocal seq
        for d in ("c2p", "p2c"):
            s = stream.get(d)
            if not s:
                continue
            seq += 1
            steps.append({
                "seq": seq, "id": "dtls_application_data_%s" % d, "protocol": "tutk",
                "channel_only": "lan", "repeatable": True,
                "observed_count": s["count"],
                "request": {
                    "transport": "udp", "dir": d,
                    "peer": anon.peer(s["peer"]),
                    "op": "dtls_%s" % d, "iotc": s["iotc"],
                    "fields": {"session_token": TOKEN_PLACEHOLDER,
                               "record_type": "application_data",
                               "epoch": s["epoch"]},
                },
            })
        stream.clear()

    for _ts, call, _fd, peer, raw in datagrams:
        info = T.parse_packet(raw)
        kind = info["kind"]
        if kind in ("unknown", "iotc_other"):
            continue
        plain, _ = T.deobfuscate(raw)
        iotc = _iotc_meta(plain)
        fields = _anon_fields(kind, info, anon)

        # Coalesce the broadcast LAN_SEARCH3 fan-out (many subnets -> one step);
        # the directed search to the printer stays its own step.
        if kind == "lan_search3" and _dir(call) == "c2p" and not _is_printer(peer, anon):
            if pending_bcast is None:
                pending_bcast = {"peers": [], "iotc": iotc, "fields": fields}
            pending_bcast["peers"].append(peer)
            continue
        flush_bcast()

        # Coalesce the encrypted AV stream (ApplicationData) per direction.
        if kind in ("dtls_c2p", "dtls_p2c") and info.get("record_type") == "application_data":
            d = _dir(call)
            s = stream.get(d)
            if s is None:
                stream[d] = {"count": 1, "peer": peer, "iotc": iotc, "epoch": info.get("epoch")}
            else:
                s["count"] += 1
            continue

        seq += 1
        steps.append({
            "seq": seq, "id": kind, "protocol": "tutk", "channel_only": "lan",
            "request": {
                "transport": "udp", "dir": _dir(call),
                "peer": anon.peer(peer) if peer else None,
                "op": kind, "iotc": iotc, "fields": fields,
            },
        })

    flush_bcast()
    flush_stream()

    return {
        "schema": "obn-wire-flow/v1",
        "meta": {
            "os": "linux",
            "network_plugin_version": version,
            "slicer_client_version": "02.07.00.55",
            "channel": "lan",
            "printer_model": model,
            "flow": "tutk_camera",
            "command": "camera_stream",
            "source": "BambuStudio",
            "protocol": "tutk",
        },
        "identity_block": {"order": [], "values": {}},
        "vars": {
            "uid": {"kind": "session", "example": UID_PLACEHOLDER},
            "printer_ip": {"kind": "session", "example": PRINTER_IP},
            "session_token": {"kind": "generated", "example": TOKEN_PLACEHOLDER},
            "p2p_nonce": {"kind": "generated", "example": NONCE_PLACEHOLDER},
        },
        "steps": steps,
    }


def _is_printer(peer, anon):
    if not peer or ":" not in peer:
        return False
    host = peer.rsplit(":", 1)[0]
    return host == anon.printer_ip


def load_socklog(path):
    """Return the ordered datagrams of the dominant TUTK fd."""
    by_fd = {}
    for ts, _tid, call, fd, peer, raw in T.iter_socklog_datagrams(path):
        if not T.is_tutk_peer(peer):
            continue
        if T.parse_packet(raw)["kind"] in ("unknown", "iotc_other"):
            continue
        by_fd.setdefault(fd, []).append((ts, call, fd, peer, raw))
    if not by_fd:
        return []
    best = max(by_fd.values(), key=len)
    best.sort(key=lambda r: r[0])
    return best


def load_pcap(path):
    from scapy.all import rdpcap, UDP, IP
    out = []
    for p in rdpcap(path):
        if UDP not in p or IP not in p:
            continue
        raw = bytes(p[UDP].payload)
        if not raw:
            continue
        if T.parse_packet(raw)["kind"] in ("unknown", "iotc_other"):
            continue
        ts = "%f" % float(p.time)
        # heuristic direction: to the printer/master = c2p
        call = "sendto"
        peer = "%s:%d" % (p[IP].dst, p[UDP].dport)
        out.append((ts, call, "0", peer, raw))
    out.sort(key=lambda r: r[0])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="socklog.txt or .pcap of a genuine TUTK session")
    ap.add_argument("-o", "--out", required=True, help="output flow.json path")
    ap.add_argument("--model", default="h2s", help="printer model (default h2s)")
    ap.add_argument("--version", default="02.07.00.50",
                    help="network_plugin_version (default 02.07.00.50)")
    args = ap.parse_args(argv)

    if args.capture.endswith(".pcap") or args.capture.endswith(".pcapng"):
        datagrams = load_pcap(args.capture)
    else:
        datagrams = load_socklog(args.capture)

    if not datagrams:
        print("no TUTK datagrams found in %s" % args.capture, file=sys.stderr)
        return 1

    fixture = build_fixture(datagrams, args.model, args.version)
    with open(args.out, "w") as fh:
        json.dump(fixture, fh, indent=2)
        fh.write("\n")
    print("wrote %s (%d steps from %d datagrams)"
          % (args.out, len(fixture["steps"]), len(datagrams)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
