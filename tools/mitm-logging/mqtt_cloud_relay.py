#!/usr/bin/env python3
"""Cloud MQTT-over-TLS (:8883) MITM relay for the Bambu cloud broker.

The genuine plugin keeps a LONG-LIVED MQTT 3.1.1 session to the region cloud
broker (e.g. us.mqtt.bambulab.com:8883) for every cloud-connected printer.
Device commands (system `ledctrl`, ams control, the RSA-signed `print`
envelopes, and the cloud-delivered `project_file` that starts a print) go to
`device/<serial>/request`; status/report pushes come back on
`device/<serial>/report`. Unlike the LAN broker (user `bblp` + access code),
the cloud broker authenticates the Bambu ACCOUNT: the CONNECT carries a
username/password (cloud uid + access token), and the print-command topics are
additionally gated by client-cert mTLS on some firmware.

This relay TLS-terminates the plugin leg (the redirect shim disables the
plugin's cert verification for the steered connection), parses each MQTT packet
in BOTH directions -- logging plugin->broker commands AND broker->plugin reports
-- and FORWARDS every packet byte-exact to the real broker over TLS so the live
session stays up: CONNECT/CONNACK, SUBSCRIBE/SUBACK, PUBLISH/PUBACK, the large
report messages, and the keepalive PINGREQ/PINGRESP all pass through unchanged.

Auth forwarding: the plugin's own CONNECT (username=uid, password=token) is
forwarded raw, so the broker authenticates exactly as if the plugin talked to it
directly -- no credential is reconstructed. The CONNECT auth *shape* is logged
(username length + auth kind, value REDACTED). If the broker requires client-cert
mTLS on the upstream TLS handshake, pass the plugin's paired cert/key with
--upstream-cert/--upstream-key (e.g. BBL_MTLS_CERT/KEY); the relay presents them
on the upstream leg only. The client (plugin) leg never needs a client cert
because the shim relaxes verification there.

Records (one NDJSON line each) go to --out, same schema import_flow.py consumes:
  {"proto":"mqtt","event":"connect","client_id":"...","auth":"username_password",
   "username_len":18,"dir":"c2s","channel":"cloud"}
  {"proto":"mqtt","event":"subscribe","topic":"device/<serial>/report","dir":"c2s"}
  {"proto":"mqtt","event":"publish","topic":"device/<serial>/request",
   "payload":"<json>","dir":"c2s","channel":"cloud"}   # command
  {"proto":"mqtt","event":"publish","topic":"device/<serial>/report",
   "payload":"<json>","dir":"s2c","channel":"cloud"}    # status report

Secrets: the CONNECT password (access token) is NEVER written to --out. Payloads
may contain tokens/urls -- the log lives in a gitignored /tmp dir and
import_flow.py anonymizes every emitted value.

Usage:
  mqtt_cloud_relay.py --broker us.mqtt.bambulab.com --listen-port 8883 \
      --out /tmp/bbl_capture/mqtt_cloud.jsonl \
      [--upstream-cert /tmp/bbl_capture/mtls/cert.pem \
       --upstream-key  /tmp/bbl_capture/mtls/key.pem]
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

LOG_LOCK = threading.Lock()
SENTINEL_LOCK = threading.Lock()
SENTINEL_DONE = False

PKT = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 8: "SUBSCRIBE",
       9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}


def log(fh, rec):
    with LOG_LOCK:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()


def signal_established(path):
    """Atomically create the cloud-established sentinel the pin patcher polls.

    Fired exactly once, when the plugin's cloud CONNECT has been read THROUGH the
    relay (upstream TLS already established, client leg accepted, CONNECT seen) --
    i.e. the cloud-broker TLS handshake genuinely completed. The event-driven
    restore in pin_patch keys off this file's appearance so the original bytes are
    put back only AFTER the handshake, never during a pre-establishment retry."""
    global SENTINEL_DONE
    if not path:
        return
    with SENTINEL_LOCK:
        if SENTINEL_DONE:
            return
        SENTINEL_DONE = True
    try:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(int(time.time())) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, path)          # atomic appearance
        sys.stderr.write(f"[mqtt-cloud] cloud session established -> sentinel {path}\n")
    except OSError as e:
        sys.stderr.write(f"[mqtt-cloud] sentinel write failed: {e}\n")


def ensure_cert(cert, key):
    if os.path.exists(cert) and os.path.exists(key):
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "3650",
         "-subj", "/CN=bambu-mitm-relay"], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def up_ctx(cert=None, key=None):
    """Upstream TLS context to the real cloud broker. Server cert is not
    verified (we are forwarding, not authenticating the broker); a client cert
    is presented when the broker enforces mTLS on the print-command topics."""
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if cert and key:
        c.load_cert_chain(cert, key)
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
    """Log the meaningful control-plane packets; forwarding stays byte-exact.

    The cloud CONNECT auth shape is logged with the credential REDACTED so we
    can report what the cloud broker actually requires without persisting the
    account token. PINGREQ/PINGRESP are not logged (pure keepalive) but are
    still forwarded by the caller so the long-lived session never times out."""
    i = 1
    while raw[i] & 0x80:
        i += 1
    i += 1
    body = raw[i:]
    try:
        if ptype == 1:  # CONNECT
            pn_len = _u16(body, 0)
            j = 2 + pn_len
            j += 1                     # protocol level
            cflags = body[j]; j += 1
            j += 2                     # keepalive
            cid_len = _u16(body, j); j += 2
            cid = body[j:j + cid_len].decode("latin1", "replace"); j += cid_len
            if cflags & 0x04:          # will flag -> skip will topic + message
                wt = _u16(body, j); j += 2 + wt
                wm = _u16(body, j); j += 2 + wm
            username = None
            has_pw = False
            if cflags & 0x80:          # username present
                ul = _u16(body, j); j += 2
                username = body[j:j + ul].decode("latin1", "replace"); j += ul
            if cflags & 0x40:          # password present
                pl = _u16(body, j); j += 2
                has_pw = True
            if username and has_pw:
                auth = "username_password"
            elif username:
                auth = "username_only"
            else:
                auth = "anonymous"     # e.g. auth carried entirely by client cert
            rec = {"proto": "mqtt", "event": "connect", "client_id": cid,
                   "auth": auth, "dir": direction, "channel": "cloud"}
            if username is not None:
                # value redacted; length/prefix only, enough to identify the
                # scheme (Bambu cloud uses the numeric uid as the username).
                rec["username_len"] = len(username)
                rec["username_is_numeric"] = username.isdigit()
            log(fh, rec)
        elif ptype == 8:  # SUBSCRIBE
            j = 2  # packet id
            topics = []
            while j < len(body):
                tl = _u16(body, j); j += 2
                topics.append(body[j:j + tl].decode("latin1", "replace")); j += tl
                j += 1  # qos
            for t in topics:
                log(fh, {"proto": "mqtt", "event": "subscribe", "topic": t,
                         "dir": direction, "channel": "cloud"})
        elif ptype == 3:  # PUBLISH (commands c2s, reports s2c)
            qos = (flags >> 1) & 0x03
            tl = _u16(body, 0)
            topic = body[2:2 + tl].decode("latin1", "replace")
            k = 2 + tl
            if qos > 0:
                k += 2  # packet id
            payload = body[k:].decode("utf-8", "replace")
            log(fh, {"proto": "mqtt", "event": "publish", "topic": topic,
                     "payload": payload, "dir": direction, "channel": "cloud"})
    except (IndexError, ValueError):
        pass


def handle(client_ss, args, fh):
    up_raw = socket.create_connection((args.broker, args.broker_port), timeout=20)
    up = up_ctx(args.upstream_cert, args.upstream_key).wrap_socket(
        up_raw, server_hostname=args.broker)
    sys.stderr.write(f"[mqtt-cloud] upstream TLS to {args.broker}:{args.broker_port} "
                     f"established (client_cert={'yes' if args.upstream_cert else 'no'})\n")

    def pump(src, dst, direction):
        try:
            while True:
                raw, ptype, flags = read_packet(src)
                if raw is None:
                    break
                parse_and_log(raw, ptype, flags, fh, direction)
                dst.sendall(raw)
                # Cloud session is established once the plugin's CONNECT has
                # traversed the relay upstream (TLS handshakes on both legs are
                # complete by now). Signal the pin patcher to restore pristine
                # code -- the handshake is done, so the live session is unaffected.
                if direction == "c2s" and ptype == 1:
                    signal_established(args.established_sentinel)
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
    ap.add_argument("--broker", required=True,
                    help="real cloud broker host, e.g. us.mqtt.bambulab.com "
                         "(from the login/profile response the wire MITM captured)")
    ap.add_argument("--broker-port", type=int, default=8883)
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8883)
    ap.add_argument("--out", default="mqtt_cloud.jsonl")
    ap.add_argument("--cert", default=None, help="relay server cert (plugin leg)")
    ap.add_argument("--key", default=None, help="relay server key (plugin leg)")
    ap.add_argument("--upstream-cert", default=None,
                    help="client cert presented to the real broker if it enforces "
                         "mTLS on print-command topics (BBL_MTLS_CERT)")
    ap.add_argument("--upstream-key", default=None,
                    help="client key for --upstream-cert (BBL_MTLS_KEY)")
    ap.add_argument("--established-sentinel", default=None,
                    help="path to atomically create when the cloud CONNECT has "
                         "traversed the relay; pin_patch PIN_PATCH_RESTORE_ON "
                         "polls it to trigger the event-driven code restore")
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

    if args.out:
        d = os.path.dirname(os.path.abspath(args.out))
        if d:
            os.makedirs(d, exist_ok=True)
    fh = open(args.out, "a", buffering=1)
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.listen_host, args.listen_port)); ls.listen(5)
    sys.stderr.write(f"[mqtt-cloud] {args.listen_host}:{args.listen_port} -> "
                     f"{args.broker}:{args.broker_port} log={args.out} "
                     f"upstream_mtls={'on' if args.upstream_cert else 'off'}\n")
    try:
        while True:
            raw, _ = ls.accept()
            try:
                ss = srv_ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as e:
                sys.stderr.write(f"[mqtt-cloud] TLS accept failed: {e}\n")
                continue
            threading.Thread(target=handle, args=(ss, args, fh), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
