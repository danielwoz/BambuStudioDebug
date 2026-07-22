#!/usr/bin/env python3
"""Deobfuscate and parse the genuine Bambu plugin's TUTK/IOTC camera protocol.

The plugin scrambles every TUTK UDP datagram with `trans_code_partial`
(key "Charlie is the d") and frames DTLS inside a 28-byte IOTC transport
header. This module ports that crypto and the frame layouts faithfully from
`obn/src/camera/oss_tutk/IotcClient.cpp` (decode_block / trans_code_partial,
LAN_SEARCH3, ctrl-0x33, master :10240 LOOKUP, and the IOTC-wrapped DTLS records).

Library:
    from tutk_decode import deobfuscate, identify, parse_packet
    plain, scope = deobfuscate(raw_bytes)   # auto-detects scramble scope
    info = parse_packet(raw_bytes)          # -> dict with 'kind' and fields

CLI:
    tutk_decode.py --selftest                 # crypto + parser self-checks
    tutk_decode.py --hex <hexstring>          # decode+parse one datagram
    tutk_decode.py --socklog session.txt      # decode+parse every TUTK datagram
"""
import argparse
import struct
import sys

KEY = b"Charlie is the d"

# ---------------------------------------------------------------------------
# trans_code_partial — TUTK packet scrambling (16-byte blocks + XOR tail)
# ---------------------------------------------------------------------------
def _rol32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _ror32(v, n):
    n &= 31
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def decode_block(inb):
    """Inverse of the plugin's encode_block: 16 scrambled bytes -> 16 plain."""
    o = list(struct.unpack("<4I", inb))
    tmp0 = _rol32(o[0], 3)
    tmp1 = _rol32(o[1], 7)
    tmp2 = _rol32(o[2], 11)
    tmp3 = _rol32(o[3], 15)
    t = [0] * 16
    t[0] = (tmp2 >> 24) & 0xFF; t[1] = (tmp2 >> 8) & 0xFF; t[2] = tmp2 & 0xFF
    t[3] = (tmp3 >> 24) & 0xFF; t[4] = (tmp3 >> 8) & 0xFF; t[5] = (tmp2 >> 16) & 0xFF
    t[6] = tmp3 & 0xFF; t[7] = (tmp3 >> 16) & 0xFF; t[8] = (tmp0 >> 16) & 0xFF
    t[9] = (tmp0 >> 8) & 0xFF; t[10] = (tmp1 >> 8) & 0xFF; t[11] = tmp0 & 0xFF
    t[12] = (tmp1 >> 16) & 0xFF; t[13] = tmp1 & 0xFF; t[14] = (tmp1 >> 24) & 0xFF
    t[15] = (tmp0 >> 24) & 0xFF
    dw = [(t[j * 4]) | (t[j * 4 + 1] << 8) | (t[j * 4 + 2] << 16) | (t[j * 4 + 3] << 24)
          for j in range(4)]
    kd = list(struct.unpack("<4I", KEY))
    rot = [1, 5, 9, 13]
    return struct.pack("<4I", *[_rol32(dw[i] ^ kd[i], rot[i]) for i in range(4)])


def encode_block(inb):
    """Scramble 16 plain bytes -> 16 wire bytes (round-trip check only)."""
    raw = list(struct.unpack("<4I", inb))
    kd = list(struct.unpack("<4I", KEY))
    rot = [1, 5, 9, 13]
    dw = [_ror32(raw[i], rot[i]) ^ kd[i] for i in range(4)]
    t = []
    for j in range(4):
        for b in range(4):
            t.append((dw[j] >> (8 * b)) & 0xFF)
    o0 = _ror32(((t[15] << 24) | (t[8] << 16) | (t[9] << 8) | t[11]) & 0xFFFFFFFF, 3)
    o1 = _ror32(((t[14] << 24) | (t[12] << 16) | (t[10] << 8) | t[13]) & 0xFFFFFFFF, 7)
    o2 = _ror32(((t[0] << 24) | (t[5] << 16) | (t[1] << 8) | t[2]) & 0xFFFFFFFF, 11)
    o3 = _ror32(((t[3] << 24) | (t[7] << 16) | (t[4] << 8) | t[6]) & 0xFFFFFFFF, 15)
    return struct.pack("<4I", o0, o1, o2, o3)


def reverse_trans_code(data, length):
    """Deobfuscate the first `length` bytes (blocks then XOR tail), in place-copy."""
    out = bytearray(data)
    n = min(length, len(out))
    full = (n // 16) * 16
    for i in range(0, full, 16):
        out[i:i + 16] = decode_block(bytes(out[i:i + 16]))
    for i in range(full, n):
        out[i] ^= KEY[i % 16]
    return bytes(out)


def trans_code(data, length):
    """Scramble the first `length` bytes (inverse of reverse_trans_code)."""
    out = bytearray(data)
    n = min(length, len(out))
    full = (n // 16) * 16
    for i in range(0, full, 16):
        out[i:i + 16] = encode_block(bytes(out[i:i + 16]))
    for i in range(full, n):
        out[i] ^= KEY[i % 16]
    return bytes(out)


# ---------------------------------------------------------------------------
# Scramble-scope detection
# ---------------------------------------------------------------------------
# DTLS-payload datagrams scramble only the first 80 bytes; control/search/master
# datagrams scramble the whole packet. The first 16 bytes (block 0) are always
# scrambled identically, so we decode block 0 first to read the IOTC flags and
# message type, then reverse the correct scope.
IOTC_MAGIC = b"\x04\x02"

# message-type triplets at bytes [8..10] of the deobfuscated IOTC header
MSGTYPES = {
    (0x01, 0x06, 0x21): "lan_search3",
    (0x02, 0x04, 0x33): "ctrl_0x33",
    (0x07, 0x10, 0x18): "master_lookup_req",
    (0x08, 0x10, 0x83): "master_lookup_reply",
    (0x07, 0x04, 0x21): "dtls_c2p",
    (0x08, 0x04, 0x12): "dtls_p2c",
    (0x11, 0x02, 0x24): "p2p_precheck1",
    (0x14, 0x02, 0x24): "p2p_precheck2",
    (0x01, 0x03, 0x21): "p2p_punch_to",
}


def deobfuscate(raw):
    """Return (plain_bytes, scope). scope is the number of bytes descrambled.

    DTLS-payload packets (IOTC flags byte == 0x0b) scramble the first 80 bytes
    and leave the rest cleartext; everything else scrambles the whole datagram.
    """
    if len(raw) < 16:
        return bytes(raw), 0
    head = reverse_trans_code(raw, 16)
    if head[0:2] != IOTC_MAGIC:
        return bytes(raw), 0
    flags = head[3]
    scope = min(len(raw), 80) if flags == 0x0B else len(raw)
    return reverse_trans_code(raw, scope), scope


def identify(plain):
    """Classify a deobfuscated IOTC datagram by its message-type triplet."""
    if len(plain) < 11 or plain[0:2] != IOTC_MAGIC:
        return "unknown"
    return MSGTYPES.get((plain[8], plain[9], plain[10]), "iotc_other")


# ---------------------------------------------------------------------------
# IOTC frame parsers (offsets are wire-confirmed in IotcClient.cpp)
# ---------------------------------------------------------------------------
def _uid(plain):
    return plain[16:36].decode("latin1")


def parse_lan_search3(plain):
    return {
        "uid": _uid(plain),
        "iotc_version": "0x%08x" % struct.unpack_from("<I", plain, 52)[0],
        "client_random": "0x%08x" % struct.unpack_from("<I", plain, 56)[0],
        "partial_mac": "0x%08x" % struct.unpack_from("<I", plain, 60)[0],
        "search_type": {1: "broadcast", 2: "directed"}.get(plain[64], plain[64])
        if len(plain) > 64 else None,
        "tail": plain[64:].hex() if len(plain) > 64 else "",
    }


def parse_ctrl_0x33(plain):
    return {
        "uid": _uid(plain),
        "session_token": plain[36:44].hex(),
        "tag": plain[48:52].hex() if len(plain) >= 52 else "",
    }


def parse_master_lookup_req(plain):
    return {
        "uid": _uid(plain),
        "nonce": plain[36:52].decode("latin1"),   # 16-byte ASCII GenShortRandomID
    }


def parse_master_lookup_reply(plain):
    out = {"uid": _uid(plain), "reflexive": None, "candidates": []}
    n = len(plain)
    if n >= 60 and plain[52] == 0x02 and plain[53] == 0x00:
        port = (plain[54] << 8) | plain[55]
        ip = ".".join(str(b) for b in plain[56:60])
        out["reflexive"] = "%s:%d" % (ip, port)
    i = 60
    while i + 8 <= n:
        if plain[i] == 0x02 and plain[i + 1] == 0x00:
            port = (plain[i + 2] << 8) | plain[i + 3]
            if port:
                ip = ".".join(str(b) for b in plain[i + 4:i + 8])
                cand = "%s:%d" % (ip, port)
                if cand != out["reflexive"]:
                    out["candidates"].append(cand)
                i += 7
        i += 1
    return out


_DTLS_CT = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
_DTLS_HS = {1: "client_hello", 2: "server_hello", 11: "certificate", 12: "server_key_exchange",
            14: "server_hello_done", 16: "client_key_exchange", 20: "finished"}


def parse_dtls(plain):
    """Parse the IOTC transport header + the first DTLS record; decode a
    ClientHello (cipher suites + extensions) when present."""
    out = {
        "iotc_header": plain[:28].hex(),
        "session_token": plain[20:28].hex(),
    }
    rec = plain[28:]
    if len(rec) < 13:
        return out
    ct = rec[0]
    out["record_type"] = _DTLS_CT.get(ct, "0x%02x" % ct)
    out["dtls_version"] = rec[1:3].hex()
    out["epoch"] = struct.unpack_from(">H", rec, 3)[0]
    out["record_len"] = struct.unpack_from(">H", rec, 11)[0]
    if ct != 22:
        return out
    hs = rec[13:]
    if len(hs) < 12:
        return out
    out["handshake_type"] = _DTLS_HS.get(hs[0], "0x%02x" % hs[0])
    if hs[0] != 1:
        return out
    body = hs[12:]
    try:
        off = 2                       # client_version
        off += 32                     # random
        sid = body[off]; off += 1 + sid
        ck = body[off]; off += 1 + ck  # dtls cookie
        csl = struct.unpack_from(">H", body, off)[0]; off += 2
        ciphers = ["0x%02x%02x" % (body[off + i], body[off + i + 1])
                   for i in range(0, csl, 2)]
        off += csl
        cl = body[off]; off += 1 + cl  # compression methods
        exts = []
        if off + 2 <= len(body):
            el = struct.unpack_from(">H", body, off)[0]; off += 2
            ex = body[off:off + el]
            i = 0
            while i + 4 <= len(ex):
                et = struct.unpack_from(">H", ex, i)[0]
                ln = struct.unpack_from(">H", ex, i + 2)[0]
                exts.append("0x%04x" % et)
                i += 4 + ln
        out["client_version"] = body[:2].hex()
        out["cipher_suites"] = ciphers
        out["extensions"] = exts
    except (IndexError, struct.error):
        out["parse_error"] = "truncated client_hello"
    return out


_PARSERS = {
    "lan_search3": parse_lan_search3,
    "ctrl_0x33": parse_ctrl_0x33,
    "master_lookup_req": parse_master_lookup_req,
    "master_lookup_reply": parse_master_lookup_reply,
    "dtls_c2p": parse_dtls,
    "dtls_p2c": parse_dtls,
}


def parse_packet(raw):
    """Deobfuscate and parse one TUTK datagram -> {'kind', 'wire_len', ...fields}."""
    plain, scope = deobfuscate(raw)
    kind = identify(plain)
    info = {"kind": kind, "wire_len": len(raw), "scramble_scope": scope}
    parser = _PARSERS.get(kind)
    if parser:
        info.update(parser(plain))
    else:
        info["plain_head"] = plain[:16].hex()
    return info


# ---------------------------------------------------------------------------
# socklog reader
# ---------------------------------------------------------------------------
def iter_socklog_datagrams(path):
    """Yield (ts, tid, call, fd, peer, raw_bytes) for send/recv lines that carry
    a non-empty payload. Field order after the call name is not assumed, so both
    the current tracer format ("… -> N data=HEX") and the earlier one
    ("… data=HEX -> N") are handled."""
    import re
    head_re = re.compile(r"^(\d+\.\d+) T(\d+) (sendto|recvfrom|sendmsg|recvmsg|send) fd=(\d+)")
    peer_re = re.compile(r"(?:to|from)=([^ ]+)")
    data_re = re.compile(r"data=([0-9a-f]*)")
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            h = head_re.match(line)
            if not h:
                continue
            ts, tid, call, fd = h.groups()
            d = data_re.search(line)
            if not d or not d.group(1):
                continue
            p = peer_re.search(line)
            peer = p.group(1) if p else ""
            yield ts, tid, call, fd, peer, bytes.fromhex(d.group(1))


def is_tutk_peer(peer):
    """A datagram peer that belongs to the TUTK transport: master :10240,
    LAN search :32761/:32100/:32108/:18604, or a printer session port."""
    if not peer or ":" not in peer:
        return False
    host, _, port = peer.rpartition(":")
    if host.startswith("127.") or host == "(null)":
        return False
    return True


# ---------------------------------------------------------------------------
# Self-checks
# ---------------------------------------------------------------------------
# The vectors are built by scrambling synthetic packets with the public
# trans_code algorithm, then asserting the decoder recovers them field-for-field
# (a round-trip that also exercises encode_block). This carries no live device
# identifiers. The same layouts were verified against genuine captured traffic
# during development (a genuine master request deobfuscates to its 20-char UID).
SYN_UID = "ABCDE12345FGHIJ67890"     # synthetic 20-char UID (not a real device)


def _build_master_req(uid):
    p = bytearray(54)
    p[0:4] = b"\x04\x02\x1c\x02"; p[4] = 0x26
    p[8:11] = b"\x07\x10\x18"
    p[16:36] = uid.encode()
    p[36:52] = b"0123456789abcdef"   # synthetic ASCII nonce
    p[52:54] = b"\x06\x00"
    return trans_code(bytes(p), len(p))


def _build_master_reply(uid):
    p = bytearray(72)
    p[0:4] = b"\x04\x02\x1d\x00"
    p[8:11] = b"\x08\x10\x83"
    p[16:36] = uid.encode()
    p[52:54] = b"\x02\x00"
    p[54:56] = (57086).to_bytes(2, "big")     # reflexive port
    p[56:60] = bytes([203, 0, 113, 1])         # reflexive ip (TEST-NET)
    p[60:68] = b"\x02\x00" + (3478).to_bytes(2, "big") + bytes([203, 0, 113, 2])
    return trans_code(bytes(p), len(p))


def _build_lan_search3(uid):
    p = bytearray(88)
    p[0:4] = b"\x04\x02\x1c\x02"; p[4] = 0x48
    p[8:11] = b"\x01\x06\x21"
    p[16:36] = uid.encode()
    p[52:56] = (0x04030304).to_bytes(4, "little")
    p[64] = 0x02
    return trans_code(bytes(p), len(p))


def _build_ctrl_0x33(uid):
    p = bytearray(52)
    p[0:4] = b"\x04\x02\x1c\x02"; p[4] = 0x24
    p[8:11] = b"\x02\x04\x33"
    p[16:36] = uid.encode()
    p[36:44] = bytes(range(8))
    p[48:52] = b"\x21\x1e\x26\x19"
    return trans_code(bytes(p), len(p))


def _build_client_hello():
    ciphers = [0xC02C, 0xC030, 0xCCAC, 0x009F]     # incl ECDHE-PSK-CHACHA20 (0xccac)
    cs = b"".join(c.to_bytes(2, "big") for c in ciphers)
    exts = b"\x00\x0a\x00\x02\x00\x1d" + b"\x00\x17\x00\x00"   # supported_groups, ext_master_secret
    body = (b"\xfe\xfd" + bytes(32) + b"\x00" + b"\x00"
            + len(cs).to_bytes(2, "big") + cs
            + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + b"\x00\x00" + b"\x00\x00\x00" \
        + len(body).to_bytes(3, "big") + body
    rec = b"\x16\xfe\xfd" + b"\x00\x00" + bytes(6) + len(hs).to_bytes(2, "big") + hs
    iotc = bytearray(28)
    iotc[0:4] = b"\x04\x02\x1c\x0b"
    iotc[8:11] = b"\x07\x04\x21"
    pkt = bytes(iotc) + rec
    return trans_code(pkt, min(len(pkt), 80))       # DTLS scrambles only first 80


def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL"), name)
        ok = ok and cond

    # crypto round-trip (exercises both encode_block and decode_block)
    sample = bytes(range(16))
    check("decode(encode(block)) == block", decode_block(encode_block(sample)) == sample)

    req = parse_packet(_build_master_req(SYN_UID))
    check("master_req kind", req["kind"] == "master_lookup_req")
    check("master_req UID recovered", req.get("uid") == SYN_UID)

    rep = parse_packet(_build_master_reply(SYN_UID))
    check("master_reply kind", rep["kind"] == "master_lookup_reply")
    check("master_reply UID echoed", rep.get("uid") == SYN_UID)
    check("master_reply reflexive present", bool(rep.get("reflexive")))
    check("master_reply candidate parsed", len(rep.get("candidates", [])) == 1)

    ls = parse_packet(_build_lan_search3(SYN_UID))
    check("lan_search3 kind", ls["kind"] == "lan_search3")
    check("lan_search3 UID recovered", ls.get("uid") == SYN_UID)
    check("lan_search3 iotc_version", ls.get("iotc_version") == "0x04030304")

    c3 = parse_packet(_build_ctrl_0x33(SYN_UID))
    check("ctrl_0x33 kind", c3["kind"] == "ctrl_0x33")
    check("ctrl_0x33 UID recovered", c3.get("uid") == SYN_UID)

    ch = parse_packet(_build_client_hello())
    check("client_hello kind", ch["kind"] == "dtls_c2p")
    check("client_hello record_type", ch.get("record_type") == "handshake")
    check("client_hello handshake_type", ch.get("handshake_type") == "client_hello")
    check("client_hello offers 0xccac", "0xccac" in ch.get("cipher_suites", []))
    check("client_hello has extensions", len(ch.get("extensions", [])) > 0)

    print("\nSELFTEST", "OK" if ok else "FAILED")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_info(info, prefix=""):
    kind = info.pop("kind")
    print("%s%s  %s" % (prefix, kind, "  ".join(
        "%s=%s" % (k, v) for k, v in info.items() if k not in ("scramble_scope",))))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Decode genuine Bambu TUTK/IOTC datagrams.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--selftest", action="store_true", help="run crypto + parser self-checks")
    g.add_argument("--hex", help="decode+parse one datagram given as hex")
    g.add_argument("--socklog", help="decode+parse every TUTK datagram in a socklog capture")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.hex:
        _print_info(parse_packet(bytes.fromhex(args.hex.strip())))
        return 0

    if args.socklog:
        for ts, tid, call, fd, peer, raw in iter_socklog_datagrams(args.socklog):
            if not is_tutk_peer(peer):
                continue
            info = parse_packet(raw)
            if info["kind"] in ("unknown", "iotc_other"):
                continue
            _print_info(info, prefix="%s %s %s->%s  " % (ts, call, fd, peer))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
