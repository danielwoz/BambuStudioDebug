#!/usr/bin/env python3
"""Native CTRL tunnel (:6000) MITM relay for a LAN Bambu printer.

libBambuSource's file browser / camera control opens a native BambuTunnelLocal
tunnel to the printer's :6000 over implicit TLS. Frames are:

    16-byte header [payload_len u32-LE][magic u32-LE][seq u32-LE][4 zero] + payload

Handshake magics (mirror <obn>/src/tunnel_local.cpp and NativeTunnelMock):
    LOGIN  client 0x0101013F  (user + access-code payload) -> login-ack 0x0001013F
    SETUP  client 0x0102013F  (ctrl json)                  -> setup-reply {"mtype":12291,"result":0}

This relay TLS-terminates :6000, parses each frame, logs the magic + payload
(the LOGIN credential payload is redacted), and forwards raw bytes to the real
printer. Once the session is Ready the actual storage LIST is served over FTPS
(the force_ftps bridge), so this relay mostly captures the handshake; pair it
with ftps_relay.py to capture the listing.

Records (one NDJSON line each) go to --out:
  {"proto":"ctrl","event":"login","magic":"0x0101013f","plen":16,"dir":"c2s"}
  {"proto":"ctrl","event":"setup","magic":"0x0102013f","payload":"{...}","dir":"c2s"}
  {"proto":"ctrl","event":"reply","magic":"0x0001013f","payload":"{...}","dir":"s2c"}

Usage:
  ctrl_relay.py --printer 192.168.1.47 --listen-port 16000 --out ctrl.jsonl
"""
import argparse
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading

LOG_LOCK = threading.Lock()

MAGIC = {0x0101013F: "login", 0x0102013F: "setup", 0x0001013F: "reply",
         0x0002013F: "reply"}


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


def pump_frames(src, dst, fh, direction):
    try:
        while True:
            hdr = recv_exact(src, 16)
            if hdr is None:
                break
            plen, magic, seq, _ = struct.unpack("<IIII", hdr)
            payload = recv_exact(src, plen) if plen else b""
            if payload is None:
                break
            ev = MAGIC.get(magic, "frame")
            rec = {"proto": "ctrl", "event": ev, "magic": "0x%08x" % magic,
                   "seq": seq, "plen": plen, "dir": direction}
            if ev == "login":
                rec["payload"] = "<user+access_code>"     # redact credential
            elif payload:
                rec["payload"] = payload.decode("utf-8", "replace")
            log(fh, rec)
            dst.sendall(hdr + payload)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass


def handle(client_ss, args, fh):
    up_raw = socket.create_connection((args.printer, args.printer_port), timeout=15)
    up = up_ctx().wrap_socket(up_raw, server_hostname=args.printer)
    t1 = threading.Thread(target=pump_frames, args=(client_ss, up, fh, "c2s"), daemon=True)
    t2 = threading.Thread(target=pump_frames, args=(up, client_ss, fh, "s2c"), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()
    for s in (client_ss, up):
        try: s.close()
        except OSError: pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--printer", required=True)
    ap.add_argument("--printer-port", type=int, default=6000)
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=16000)
    ap.add_argument("--out", default="ctrl.jsonl")
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
    sys.stderr.write(f"[ctrl-relay] {args.listen_host}:{args.listen_port} -> "
                     f"{args.printer}:{args.printer_port} log={args.out}\n")
    try:
        while True:
            raw, _ = ls.accept()
            try:
                ss = srv_ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as e:
                sys.stderr.write(f"[ctrl-relay] TLS accept failed: {e}\n")
                continue
            threading.Thread(target=handle, args=(ss, args, fh), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
