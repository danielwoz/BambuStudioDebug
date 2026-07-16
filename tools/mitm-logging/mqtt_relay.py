#!/usr/bin/env python3
"""MQTT-over-TLS (:8883) MITM relay for a Bambu broker (LAN printer or cloud).

The genuine plugin drives the printer over MQTT 3.1.1 on :8883 -- device commands
(system ledctrl, ams control, and the RSA-signed `print` envelopes) go to
`device/<serial>/request`; status comes back on `device/<serial>/report`. On the
LAN the only credential is user `bblp` + the 8-char access code (no Bambu
account). This relay TLS-terminates the client, parses each MQTT packet
(CONNECT / SUBSCRIBE / PUBLISH), logs the control-plane publishes, and forwards
the raw bytes to the real broker over TLS.

Combine with the redirect shim (steer the broker host + :8883 to this relay) for
a live plugin capture, or point any MQTT client at it for a smoke test.

Records (one NDJSON line each) go to --out:
  {"proto":"mqtt","event":"connect","client_id":"...","dir":"c2s"}
  {"proto":"mqtt","event":"subscribe","topic":"device/<serial>/report","dir":"c2s"}
  {"proto":"mqtt","event":"publish","topic":"device/<serial>/request","payload":"<json>","dir":"c2s"}

Usage:
  mqtt_relay.py --broker 192.168.1.209 --listen-port 8883 --out mqtt.jsonl \
                [--cert C.pem --key K.pem]
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import threading

LOG_LOCK = threading.Lock()

PKT = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 8: "SUBSCRIBE",
       9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}


def log(fh, rec):
    with LOG_LOCK:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()


def ensure_cert(cert, key):
    if os.path.exists(cert) and os.path.exists(key):
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "3650",
         "-subj", "/CN=bambu-mitm-relay"], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def up_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return c


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        b = sock.recv(n - len(buf))
        if not b:
            return None
        buf.extend(b)
    return bytes(buf)


def read_packet(sock):
    """Read one whole MQTT control packet. Returns (raw_bytes, type, flags)."""
    h = recv_exact(sock, 1)
    if not h:
        return None, None, None
    b1 = h[0]
    ptype = b1 >> 4
    flags = b1 & 0x0F
    # remaining length varint
    mult = 1
    rem = 0
    lenbytes = bytearray()
    while True:
        eb = recv_exact(sock, 1)
        if not eb:
            return None, None, None
        lenbytes.append(eb[0])
        rem += (eb[0] & 0x7F) * mult
        if not (eb[0] & 0x80):
            break
        mult *= 128
        if mult > 128 ** 4:
            return None, None, None
    body = recv_exact(sock, rem) if rem else b""
    if body is None:
        return None, None, None
    return h + bytes(lenbytes) + body, ptype, flags


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def parse_and_log(raw, ptype, flags, fh, direction):
    """Log the meaningful control-plane packets; forwarding is byte-exact."""
    body_off = 1
    i = 1
    while raw[i] & 0x80:
        i += 1
    i += 1
    body = raw[i:]
    try:
        if ptype == 1:  # CONNECT
            # protocol name
            pn_len = _u16(body, 0)
            j = 2 + pn_len + 1  # + version
            cflags = body[j]; j += 1
            j += 2  # keepalive
            cid_len = _u16(body, j); j += 2
            cid = body[j:j + cid_len].decode("latin1", "replace")
            log(fh, {"proto": "mqtt", "event": "connect", "client_id": cid,
                     "dir": direction})
        elif ptype == 8:  # SUBSCRIBE
            j = 2  # packet id
            topics = []
            while j < len(body):
                tl = _u16(body, j); j += 2
                topics.append(body[j:j + tl].decode("latin1", "replace")); j += tl
                j += 1  # qos
            for t in topics:
                log(fh, {"proto": "mqtt", "event": "subscribe", "topic": t,
                         "dir": direction})
        elif ptype == 3:  # PUBLISH
            qos = (flags >> 1) & 0x03
            tl = _u16(body, 0)
            topic = body[2:2 + tl].decode("latin1", "replace")
            k = 2 + tl
            if qos > 0:
                k += 2  # packet id
            payload = body[k:].decode("utf-8", "replace")
            log(fh, {"proto": "mqtt", "event": "publish", "topic": topic,
                     "payload": payload, "dir": direction})
    except (IndexError, ValueError):
        pass


def handle(client_ss, args, fh):
    up_raw = socket.create_connection((args.broker, args.broker_port), timeout=15)
    up = up_ctx().wrap_socket(up_raw, server_hostname=args.broker)

    def pump(src, dst, direction):
        try:
            while True:
                raw, ptype, flags = read_packet(src)
                if raw is None:
                    break
                parse_and_log(raw, ptype, flags, fh, direction)
                dst.sendall(raw)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try: s.shutdown(socket.SHUT_RDWR)
                except OSError: pass

    t1 = threading.Thread(target=pump, args=(client_ss, up, "c2s"), daemon=True)
    t2 = threading.Thread(target=pump, args=(up, client_ss, "s2c"), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()
    for s in (client_ss, up):
        try: s.close()
        except OSError: pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--broker", required=True)
    ap.add_argument("--broker-port", type=int, default=8883)
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8883)
    ap.add_argument("--out", default="mqtt.jsonl")
    ap.add_argument("--cert", default=None)
    ap.add_argument("--key", default=None)
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    cert = args.cert or os.path.join(here, "relay_cert.pem")
    key = args.key or os.path.join(here, "relay_key.pem")
    ensure_cert(cert, key)

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(cert, key)
    try:
        srv_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass

    fh = open(args.out, "a", buffering=1)
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.listen_host, args.listen_port)); ls.listen(5)
    sys.stderr.write(f"[mqtt-relay] {args.listen_host}:{args.listen_port} -> "
                     f"{args.broker}:{args.broker_port} log={args.out}\n")
    try:
        while True:
            raw, _ = ls.accept()
            try:
                ss = srv_ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as e:
                sys.stderr.write(f"[mqtt-relay] TLS accept failed: {e}\n")
                continue
            threading.Thread(target=handle, args=(ss, args, fh), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
