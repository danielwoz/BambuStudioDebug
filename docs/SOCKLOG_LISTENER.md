# Socket-flow listener (`socklog`) — TUTK camera capture

The REST wire-logging in [`MITM_LOGGING.md`](MITM_LOGGING.md) captures the
genuine plugin's HTTPS traffic to `api.bambulab.com`. It cannot see the
**camera path**. The plugin streams video over the ThroughTek **TUTK/IOTC**
protocol, which:

- **self-resolves DNS** — it queries its own region master hostnames, so the
  `getaddrinfo` redirect in `mitm_redirect.so` never steers it through the proxy;
- runs as **raw UDP** to the printer and to the master servers, not HTTPS to a
  known host, so there is no TLS leg to terminate.

`socklog` records that traffic one layer lower — at the socket syscalls — so the
camera flow can be captured, decoded, and imported into OBN's wire-compliance
harness as a `obn-wire-flow/v1` fixture.

---

## 1. How it works

`socklog/socklog.so` is an `LD_PRELOAD` shim that interposes the BSD socket
calls (`socket`, `bind`, `connect`, `setsockopt`, `send`, `sendto`, `sendmsg`,
`recvfrom`, `recvmsg`) and appends one line per call to `$SOCKLOG_OUT`:
timestamp, thread id, fd, peer address, byte count, and the payload hex.

It only wraps libc entry points — no ptrace, no code patching — so it does not
trip the genuine plugin's tamper detection (the same reason the REST redirect is
a preload shim, not a debugger).

```
… sendto fd=126 to=45.79.40.130:10240 len=54  -> 54  data=ee2f8cec…   master LOOKUP
… sendto fd=126 to=255.255.255.255:32761 len=88 -> 88 data=6e4c9d8c…  broadcast LAN_SEARCH3
… sendto fd=126 to=192.168.1.2:36337 len=88  -> 88  data=6e4c9d8c…  directed LAN_SEARCH3
… sendto fd=126 to=192.168.1.2:36337 len=285 -> 285 data=6e6c5df2…  DTLS ClientHello
… recvfrom fd=126 from=192.168.1.2:36337 -> 1117 data=4e6f4d12…     DTLS ApplicationData (video)
```

Every TUTK datagram is scrambled with `trans_code_partial` (key
`"Charlie is the d"`), and DTLS records ride inside a 28-byte IOTC transport
header. `tutk_decode.py` ports that crypto and the frame layouts.

### The TUTK camera flow (observed, genuine H2S)

```
1  master LOOKUP        UDP :10240   register UID with region master servers
2  LAN_SEARCH3          UDP :32761   broadcast to find the printer on the LAN
3  LAN_SEARCH3          UDP :<sess>  directed to the printer's session port
4  DTLS ClientHello     UDP :<sess>  ECDHE-PSK-CHACHA20-POLY1305 (0xccac), x25519
5  ctrl-0x33            UDP :<sess>  session-token handshake
6  LOOKUP reply         UDP :10240   reflexive addr + P2P candidate list
7  DTLS ServerHello …   UDP :<sess>  handshake flights + Finished
8  ApplicationData      UDP :<sess>  encrypted AV login / control / H.264 video
```

---

## 2. Capture a genuine flow

```
tools/mitm-logging/capture_tutk.sh --studio <bambu-studio> --display :0 --out <dir>
```

It builds `socklog.so`, launches the fork with `socklog.so` (+ `abi_tap.so`)
preloaded, and writes `<dir>/socklog.txt`. Open the printer's camera, let a few
seconds of video run, then quit. `SOCKLOG_MAX` caps the logged payload bytes
(default 2048; raise it to keep full video frames, lower it to keep the log
small — the decode only needs the first ~80 bytes of each datagram).

Manual equivalent:

```
SOCKLOG_OUT=session.txt SOCKLOG_MAX=2048 \
  LD_PRELOAD=tools/mitm-logging/socklog/socklog.so <bambu-studio>
```

---

## 3. Decode

```
tools/mitm-logging/tutk_decode.py --socklog session.txt   # whole session
tools/mitm-logging/tutk_decode.py --hex <datagram-hex>     # one datagram
tools/mitm-logging/tutk_decode.py --selftest               # crypto + parser checks
```

`tutk_decode.py` deobfuscates each datagram and parses LAN_SEARCH3, ctrl-0x33,
the master LOOKUP request/reply (UID, nonce, reflexive addr, candidate list) and
the IOTC-wrapped DTLS records (record header, and for a ClientHello the offered
cipher suites + extensions). It is both a CLI and an importable library
(`deobfuscate`, `identify`, `parse_packet`). The self-checks round-trip
synthetic packets through the scramble and assert the decoder recovers them —
e.g. a master request must deobfuscate back to its plaintext UID, and a
ClientHello must parse out the offered `0xccac` cipher. The layouts were
verified against genuine captured traffic during development.

The crypto is ported faithfully from OBN's
`src/camera/oss_tutk/IotcClient.cpp` (`decode_block` / `trans_code_partial` and
the wire-confirmed frame offsets); no ThroughTek SDK is involved.

---

## 4. Import as an OBN fixture

```
tools/mitm-logging/import_tutk_flow.py session.txt \
    -o <obn>/tests/wire-fixtures/linux/<ver>/lan/<model>/tutk_camera/flow.json \
    --model <model> --version <ver>
```

It isolates the TUTK UDP session, orders the datagrams, and emits an
`obn-wire-flow/v1` fixture: `meta` / `identity_block` / `vars` / `steps`, one
step per wire event (direction, peer, IOTC message type, decoded fields). The
broadcast fan-out collapses into one repeatable step, and the encrypted AV
stream collapses into one repeatable step per direction with an observed count.

**Anonymization.** A raw `socklog.txt` contains live secrets. The importer
redacts them all before writing:

| Captured value                | Placeholder in the fixture |
|-------------------------------|----------------------------|
| cloud UID                     | `TUTKUID0000000000000`     |
| session token, p2p nonce      | zeros                      |
| client random, partial MAC, authkey, DTLS randoms | redacted |
| printer LAN IP                | `192.168.1.2`              |
| reflexive / candidate / master public IPs | `203.0.113.x` (TEST-NET) |

The output is a pure log of the wire shape — no live values, no prose notes.
Never commit a raw `socklog.txt`; commit only the redacted fixture.

---

## 5. Harness integration

The fixture registers automatically as a ctest
(`wire_linux_<ver>_lan_<model>_tutk_camera`). The wire-compliance harness
(`tests/wire_compliance_test.cpp`) dispatches on `meta.flow`; there is no
`tutk_camera` driver yet, so it returns 77 → **ctest Skipped**, exactly like the
placeholder `ssdp`/`mqtt` flows. The fixture is the captured contract; a driver
that replays the OSS TUTK client and diffs against these steps is the next step
(the OBN camera transport lives in `src/camera/oss_tutk/`).

A sample fixture built from a genuine H2S session ships at
`tests/wire-fixtures/linux/02.07.00.50/lan/h2s/tutk_camera/flow.json`.
