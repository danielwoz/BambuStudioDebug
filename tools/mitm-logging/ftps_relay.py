#!/usr/bin/env python3
"""Implicit-FTPS (:990) MITM relay for a LAN Bambu printer.

The genuine plugin uploads the print-ready 3mf (STOR) and lists printer storage
(LIST) over implicit FTPS on the printer's :990, authenticating with user `bblp`
and the 8-char LAN access code (no Bambu account needed). This relay sits
between the plugin and the printer: it TLS-terminates the control channel, parses
the FTP commands (USER/PASS/PBSZ/PROT/PASV/STOR/LIST), rewrites PASV so the data
channel also flows through the relay, TLS-terminates that too, logs the LIST
listing / STOR file (name+size+md5), and forwards everything to the real printer.

Combine with the redirect shim (steer :990 -> this relay) for a live plugin
capture, or point any FTPS client at it for a smoke test. LAN-only; the access
code is the only credential.

Records (one NDJSON line each) go to --out:
  {"proto":"ftps","event":"LIST","path":"/","listing":"<raw ls>","dev":"<serial>"}
  {"proto":"ftps","event":"STOR","filename":"x.3mf","size":N,"md5":"<hex>","dev":"<serial>"}

Usage:
  ftps_relay.py --printer 192.168.1.209 --dev 0938BC582502312 \
                --listen-port 9990 --out ftps.jsonl [--cert C.pem --key K.pem]
"""
import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading

LOG_LOCK = threading.Lock()


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
        c.set_ciphers("DEFAULT:@SECLEVEL=0")   # printers use legacy suites
    except ssl.SSLError:
        pass
    return c


def handle(client_ss, args, fh, srv_ctx):
    """Relay one control session."""
    printer = args.printer
    dev = args.dev or ""
    # upstream control channel: implicit TLS to printer:990. One context for the
    # whole session so the data channel can resume the control TLS session
    # (Bambu's vsFTPd sets ssl_reuse_required=YES and 522-rejects a fresh one).
    uctx = up_ctx()
    up_raw = socket.create_connection((printer, args.printer_port), timeout=15)
    up = uctx.wrap_socket(up_raw, server_hostname=printer)

    data_state = {"pasv": None}  # (printer_ip, printer_port)
    pending = {"op": None, "arg": None}

    def pump_data(client_data_conn):
        """A client connected to our rewritten PASV port. Dial the printer's real
        data port, TLS both, pump, and log LIST/STOR payloads."""
        pip, pport = data_state["pasv"]
        praw = socket.create_connection((pip, pport), timeout=15)
        # resume the control-channel TLS session (ssl_reuse_required)
        pdata = uctx.wrap_socket(praw, server_hostname=printer, session=up.session)
        cdata = srv_ctx.wrap_socket(client_data_conn, server_side=True)
        op, arg = pending["op"], pending["arg"]
        buf = bytearray()
        md5 = hashlib.md5()
        size = 0

        def c2p():
            nonlocal size
            try:
                while True:
                    b = cdata.recv(65536)
                    if not b:
                        break
                    size += len(b); md5.update(b)
                    pdata.sendall(b)
            except OSError:
                pass
            try: pdata.unwrap()
            except OSError: pass
            try: pdata.shutdown(socket.SHUT_WR)
            except OSError: pass

        def p2c():
            try:
                while True:
                    b = pdata.recv(65536)
                    if not b:
                        break
                    if op == "LIST":
                        buf.extend(b)
                    cdata.sendall(b)
            except OSError:
                pass
            try: cdata.unwrap()
            except OSError: pass
            try: cdata.shutdown(socket.SHUT_WR)
            except OSError: pass

        t1 = threading.Thread(target=c2p, daemon=True)
        t2 = threading.Thread(target=p2c, daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        try: cdata.close()
        except OSError: pass
        try: pdata.close()
        except OSError: pass
        if op == "LIST":
            log(fh, {"proto": "ftps", "event": "LIST", "path": arg or "/",
                     "listing": buf.decode("utf-8", "replace"), "dev": dev})
        elif op == "STOR":
            log(fh, {"proto": "ftps", "event": "STOR", "filename": arg,
                     "size": size, "md5": md5.hexdigest(), "dev": dev})

    def client_to_printer():
        try:
            while True:
                line = b""
                while not line.endswith(b"\r\n"):
                    ch = client_ss.recv(1)
                    if not ch:
                        return
                    line += ch
                txt = line.decode("latin1").strip()
                cmd = txt.split(" ", 1)[0].upper()
                arg = txt[len(cmd):].strip()
                # STOR/LIST/NLST are logged by pump_data with md5/listing; log the
                # rest of the control commands here.
                if cmd in ("USER", "PASS", "PBSZ", "PROT", "CWD", "TYPE"):
                    ev = {"proto": "ftps", "event": cmd, "dev": dev}
                    if cmd == "PASS":
                        ev["arg"] = "<access_code>"     # never log the real code
                    elif arg:
                        ev["arg"] = arg
                    log(fh, ev)
                if cmd in ("STOR", "LIST", "NLST"):
                    pending["op"] = "LIST" if cmd in ("LIST", "NLST") else "STOR"
                    pending["arg"] = arg or "/"
                up.sendall(line)
        except OSError:
            pass
        finally:
            try: up.close()
            except OSError: pass

    def printer_to_client():
        try:
            while True:
                line = b""
                while not line.endswith(b"\r\n"):
                    ch = up.recv(1)
                    if not ch:
                        return
                    line += ch
                txt = line.decode("latin1").strip()
                if txt.startswith("227"):
                    # 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
                    import re
                    m = re.search(r"\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)", txt)
                    if m:
                        pip = m.group(1).replace(",", ".")
                        pport = (int(m.group(2)) << 8) + int(m.group(3))
                        data_state["pasv"] = (pip, pport)
                        # open a local data listener and rewrite the reply
                        dl = socket.socket(); dl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        dl.bind(("127.0.0.1", 0)); dl.listen(1)
                        lport = dl.getsockname()[1]
                        hi, lo = (lport >> 8) & 0xFF, lport & 0xFF
                        rewritten = "227 Entering Passive Mode (127,0,0,1,%d,%d).\r\n" % (hi, lo)

                        def accept_data():
                            try:
                                conn, _ = dl.accept()
                                dl.close()
                                pump_data(conn)
                            except OSError:
                                pass
                        threading.Thread(target=accept_data, daemon=True).start()
                        client_ss.sendall(rewritten.encode("latin1"))
                        continue
                client_ss.sendall(line)
        except OSError:
            pass
        finally:
            try: client_ss.close()
            except OSError: pass

    t1 = threading.Thread(target=client_to_printer, daemon=True)
    t2 = threading.Thread(target=printer_to_client, daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--printer", required=True)
    ap.add_argument("--printer-port", type=int, default=990)
    ap.add_argument("--dev", default="")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=9990)
    ap.add_argument("--out", default="ftps.jsonl")
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
    sys.stderr.write(f"[ftps-relay] :{args.listen_port} -> {args.printer}:{args.printer_port} "
                     f"(implicit TLS) log={args.out}\n")
    try:
        while True:
            raw, _ = ls.accept()
            try:
                ss = srv_ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as e:
                sys.stderr.write(f"[ftps-relay] TLS accept failed: {e}\n")
                continue
            threading.Thread(target=handle, args=(ss, args, fh, srv_ctx), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
