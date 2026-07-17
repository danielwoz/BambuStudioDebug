# MITM wire-logging (`obn-wire-flow/v1` capture)

BambuStudioDebug is a BambuStudio fork whose job is to record what the
**genuine, closed-source Bambu network plugin** puts on the wire, in the exact
schema consumed by the open-bamboo-networking (OBN) wire-compliance harness
(`obn-wire-flow/v1`). Those recordings are the **golden GENUINE traces**: the
contract the OSS network library must reproduce message-for-message (method /
path / query / header set + order / body shape).

The intended use: a user hits a problem with the OBN plugin, runs
BambuStudioDebug (which uses the *genuine* plugin), reproduces the issue,
exports a fixture with `import_flow.py`, drops it into the OBN harness, and the
harness replays it against OSS and shows **exactly where OBN diverges from
genuine**.

This document describes the capture architecture, the log format, the
import-to-fixture mapping, the runtime capture directory and anonymization, and
the end-to-end verification. It is **Linux-first**; macOS/Windows notes are at
the end.

---

## 1. Where the MITM sits — decision

**The capture is a transport-level MITM of the genuine plugin's TLS traffic, not
a tap inside any plugin.** The genuine plugin is closed source; we cannot add a
recorder to it, and we specifically want *its* bytes, not the OSS plugin's. So
we intercept at the socket/TLS layer, below the plugin:

```
BambuStudio (fork)  ->  genuine libbambu_networking.so  ->  libcurl/OpenSSL
        |                                                        |
        |  LD_PRELOAD tools/mitm-logging/mitm_redirect.so        |
        |  - getaddrinfo: api.bambulab.com -> 127.0.0.2 sentinel |
        |  - connect: sentinel:443 -> 127.0.0.1:$REDIRECT_443    |
        |  - SSL_set_verify -> VERIFY_NONE (redirected leg only)  |
        v                                                        v
   mitmdump  --mode reverse:https://api.bambulab.com  (wire_addon.py)
        |   terminates TLS with its own CA-minted api.bambulab.com cert,
        |   logs the decrypted request/response, forwards to the real API
        v
   real api.bambulab.com
```

Why transport-level and not an ABI tap or an OBN choke point:

- BambuStudio does no networking itself; it delegates across a C ABI to the
  plugin. A tap in `NetworkAgent` would only see ABI arguments, never the wire
  bytes, header **order**, or exact paths the fixtures assert.
- Recording inside the OBN plugin captures **OBN**, which is backwards — OBN is
  the thing under test. We need the genuine reference.
- A transport MITM sees the true genuine wire, including header ordering
  (Cloudflare/JA4H fingerprint the header **set and order**).

### Hostname scoping (why login still works)

`api.bambulab.com` shares Cloudflare front-ends with `bambulab.com` and
`makerworld.com` (the sign-in webview). If we redirected by IP we would also
break the webview's TLS. Instead the shim rewrites **only the
`api.bambulab.com` hostname** at `getaddrinfo` time to a loopback sentinel
(`127.0.0.2`); `connect()` then steers that sentinel's `:443` to the local
mitmdump. Every other host resolves and connects normally with a real
certificate, so the GnuTLS login webview is untouched. IPv6 for the API is
black-holed to `::1` so the client falls back to the v4 sentinel rather than
reaching the real API over v6 and bypassing capture.

### Trust on the redirected leg

The genuine plugin uses libcurl/OpenSSL with its own CA bundle and would reject
mitmproxy's interception certificate. The shim overrides `SSL_CTX_set_verify` /
`SSL_set_verify` to `VERIFY_NONE` **on the plugin's OpenSSL leg only**. This is
scoped to the redirected API connection; the webview (GnuTLS, real server) is
unaffected. An equivalent alternative is to append the mitmproxy CA
(`~/.mitmproxy/mitmproxy-ca-cert.pem`) to the plugin's CA bundle; disabling
verification on the redirected leg is simpler and equally contained.

### Cloud MQTT (long-lived device session)

Cloud-connected printers are driven over a persistent MQTT 3.1.1 session to the
region cloud broker (`us.mqtt.bambulab.com:8883`, region from the login/profile
response). Device commands (`system` ledctrl/ams, RSA-signed `print` envelopes,
and the cloud-delivered `project_file` that starts a print) publish to
`device/<serial>/request`; status reports return on `device/<serial>/report`.

The shim redirects it exactly like the REST leg but on a second sentinel: when
`REDIRECT_MQTT8883` is set, `getaddrinfo` rewrites any `*.mqtt.bambulab.com`
host to `127.0.0.3` and `connect()` steers that sentinel's `:8883` to
`mqtt_cloud_relay.py`. The relay TLS-terminates, parses each packet **both
directions** (commands and reports), and forwards every packet byte-exact —
CONNECT/SUBSCRIBE/PUBLISH, the large report messages, and the PINGREQ/PINGRESP
keepalive — so the session never drops.

**Auth.** The cloud CONNECT authenticates the Bambu *account*:
username = numeric cloud uid, password = access token. The plugin's own CONNECT
is forwarded raw, so the broker authenticates exactly as if the plugin talked to
it directly (no credential is reconstructed); the relay logs only the auth
*shape* with the token redacted. If a firmware enforces client-cert **mTLS** on
the print-command topics, pass the plugin's paired cert with
`--upstream-cert/--upstream-key` (BBL_MTLS_CERT/KEY) and the relay presents it on
the upstream leg only.

**Trust — the cloud channel is certificate-pinned, inside the network plugin.**
Unlike the REST leg, the cloud MQTT TLS verifies the broker cert against a **CA
the plugin carries itself**, not the system trust store or any file the process
can be pointed at. Every file/store approach was tried and the relay leaf was
still rejected with `TLSV1_ALERT_UNKNOWN_CA`, the relay CA's subject hash
**never** looked up:

- `SSL_CERT_FILE` / `SSL_CERT_DIR`: ignored.
- Relay CA installed in the **system store** (`/etc/ssl/certs`, root — hashed
  `<hash>.0` symlink and regenerated `ca-certificates.crt`): rejected.
- The shim's `MITM_CA_DIR` redirect of every CA-store read (`<hash>.N`,
  `cert.pem`, `ca-certificates.crt`) under `/etc/ssl/`, any `.../certs/`, and the
  compiled OpenSSLDIR, across the `open`/`openat`/`fopen`/`stat`/`opendir`
  families and raw `syscall()`: redirects Studio's *own* REST OpenSSL yet the
  MQTT leg never reads the relay CA through any of them.

**Where the pin actually lives (corrected).** An earlier note attributed the
cloud MQTT TLS to `libBambuSource.so`. An execution backtrace on the outbound
`connect()` to the cloud-broker sentinel (`tools/mitm-logging/conn_origin_trace.c`,
`dlsym`-interposed `connect()` — no ptrace) resolves **every** caller frame to
`libbambu_networking.so`. The cloud MQTT client, its TLS, and the pin are inside
the **network plugin's own statically-linked OpenSSL** — VMProtect-packed at
rest, unpacked to plain x86 (strings encrypted) at runtime, with all crypto
symbols internal (zero dynamic symbols / no GOT). BambuSource is a separate
matter: it statically links OpenSSL too but **exports** it under a `tutk_third_`
prefix with real PLT/GOT entries, so `tools/mitm-logging/pin_bypass.c` interposes
BambuSource's `tutk_third_ssl_verify_cert_chain` to force-accept — verified to
bind under `LD_DEBUG=bindings`. That lever works for BambuSource's TLS legs
(libcurl / TUTK P2P) but is **inert for the cloud MQTT device session**, since
that session does not route through BambuSource — confirmed by the interposer's
verify hook never firing during the MQTT handshake while the redirect delivered
the connection to the relay.

Consequences for a TLS-interception capture of the cloud MQTT session:

- (a) mosquitto-layer hook / (b) GOT-PLT interpose: **impossible** — the plugin's
  OpenSSL has no dynamic import to hook (no libmosquitto; verify symbols are
  internal to the packed image).
- (c) runtime code patch of the plugin's verify decision: **implemented and
  working** — see "Defeating the pin" below. The unpacked OpenSSL is plain x86
  (not virtualized), the verify branch is located dynamically, and the patch
  survives the plugin's VMProtect integrity pass by timing.

Confirming test: launched **without** the MQTT redirect, the plugin connects to
the real broker with no error — its pinned CA trusts the genuine broker — so the
sole MITM blocker is that the relay leaf is not signed by that pinned CA.

Everything up to that pinning boundary is verified and works: the transport
redirect (the plugin's `us.mqtt.bambulab.com` connection lands on the relay), the
relay's TLS-terminate + bidirectional parse + byte-exact forward + keepalive, the
relay's upstream TLS 1.3 to the real broker, and the importer → harness path
(loopback + `ledctrl`/`project_file` fixtures). The `MITM_CA_DIR` redirect
remains useful for other statically-linked-OpenSSL plugins that read their CA
store from the filesystem (not pinned).

**Cloud report content is instead captured at the ABI boundary**, above TLS,
where pinning is irrelevant: the `abi_tap` wraps the plugin's inbound
`on_message` / `on_local_message` / `on_user_message` callbacks and logs each
status report (`"dir":"report"`) before forwarding it to Studio unchanged. Run
`LD_PRELOAD=abi_tap.so` alone (no redirect) and the real cloud/LAN session's
commands **and** reports are recorded in the clear — verified live against a real
H2S (periodic cloud reports at rest + a full chamber-light `ledctrl` round-trip).

### Defeating the pin — runtime x86 patch (approach c, implemented)

The pin *can* be defeated in-process, capturing the genuine cloud MQTT wire
through the existing relay, with **no ptrace and no on-disk change to the
plugin**. Three preload objects (all built by `build_pin_bypass.sh`, none
committed):

1. **Localize the pin dynamically** (`alert_trace.c`). The rejected leaf makes
   the plugin's OpenSSL send a *plaintext* handshake-phase fatal alert record —
   `15 03 03 00 02 02 30` (level fatal, desc `0x30` = unknown_ca). The plugin
   writes it through libc `write`/`send`, so interposing those and matching the
   byte pattern yields a `backtrace()` at the emission site. Every plugin frame
   resolves via `dladdr` into the unpacked region; the chain is OpenSSL's
   `tls_process_server_certificate` → `SSLfatal(ssl_x509err2alert(verify_result),
   CERTIFICATE_VERIFY_FAILED)` → alert dispatch → `write`.

2. **Dump + disassemble the unpacked code.** Root-read (no ptrace/attach —
   `open`+`pread` of `/proc/PID/mem`, which does not set `TracerPid` and does not
   trip the plugin's anti-debug) the anonymous `r-xp` region that the backtrace
   frames fall in, and disassemble it. The verify branch is:

   ```
   call ssl_verify_cert_chain          ; i = verify(s, sk)
   mov  %eax,%r13d
   mov  0x560(%r12),%eax               ; s->verify_mode
   test %eax,%eax ; je  skip           ; VERIFY_NONE -> no check
   test %r13d,%r13d
   jle  fail                           ; i <= 0 -> unknown_ca   <== the gate
   ```

   Preceded by an 18-byte, image-unique lead signature ending at
   `test %r13d,%r13d`, so the `jle` is found by content, ASLR-independent.

3. **Patch it at runtime** (`pin_patch.c`, `LD_PRELOAD`). A constructor thread
   scans **only the plugin's own mapped span** (bounded by the
   `libbambu_networking.so` mappings — the identical OpenSSL verify branch exists
   in Studio's *own* OpenSSL too, and must not be touched) for the signature and
   NOP-6es the `jle`. That lets `ssl_verify_cert_chain` (and Bambu's app pin
   callback) run fully but removes the fatal-on-failure abort, so the handshake
   completes.

**Surviving VMProtect's integrity check — the one real wall.** Writing those
bytes at startup crashes the plugin within ~1 s (confirmed a **content** check,
not a page-permission one: writing via `/proc/self/mem` with the page left
`r-xp` crashes identically; a locate-only dry-run never does). The check is
**one-time**, during plugin init. `PIN_PATCH_DELAY_MS` therefore locates the
branch immediately but arms the write only after the delay (~60 s — past init and
login). With the integrity pass already complete, the patch takes and holds; the
cloud MQTT reconnect then completes through the relay. Studio's own later TLS
keeps working, confirming the check does not re-run per handshake.

Result (live, genuine plugin + real H2S, idle): the relay logs
`upstream TLS to us.mqtt.bambulab.com:8883 established` with **no**
`TLSV1_ALERT_UNKNOWN_CA`, and the real cloud device session is captured —
`CONNECT slicer:<uid>:… (username+token)`, `SUBSCRIBE device/<serial>/report`,
and bidirectional `request`/`report` publishes (`pushall`, `get_version`,
`get_access_code`, `app_cert_install`, `push_status`). `import_flow.py --flow
device_command` → fixture → `wire_compliance_test` → `WIRE-COMPLIANCE OK`.

    LD_PRELOAD="pin_patch.so:mitm_redirect.so" REDIRECT_MQTT8883=9883 \
        PIN_PATCH_DELAY_MS=60000 <studio>          # + mqtt_cloud_relay.py on :9883

The one-time-integrity timing is the crux: an immediate patch trips it; a patch
armed after init does not. Prereqs to load the genuine plugin under a self-built
Studio: `app.ignore_module_cert=1` in `BambuStudio.conf` (skip the same-publisher
module-signature check) and a plugin whose version family matches Studio's
`SLIC3R_VERSION` first 8 chars (`02.07.01`).
`import_flow.py --flow device_command` folds the report in as `captured_reports`
context while the outbound command stays the harness assertion. See
`tools/mitm-logging/abi_tap/README.md`.

---

## 2. Components (`tools/mitm-logging/`)

| File | Role | Protocol |
|------|------|----------|
| `mitm_redirect.c`, `build_redirect.sh` | LD_PRELOAD transport shim; steers `:443` (api.bambulab.com) and, when the paired `REDIRECT_8883/990/6000` env is set, the LAN transports to local relays. | all |
| `wire_addon.py` | mitmdump addon; one NDJSON line per REST request. | HTTPS |
| `ssdp_sniff.py` | passive UDP `:2021` sniffer for printer NOTIFY broadcasts (no TLS). | SSDP |
| `mqtt_relay.py` | TLS-terminating MQTT 3.1.1 relay for `:8883` (LAN printer). | MQTT |
| `mqtt_cloud_relay.py` | TLS-terminating relay for the region **cloud** broker `*.mqtt.bambulab.com:8883`; logs device commands + status reports both directions, introspects the CONNECT auth (uid/token, redacted), forwards the raw long-lived session. | cloud MQTT |
| `ftps_relay.py` | implicit-FTPS relay for `:990` (control + PASV data, TLS session reuse). | FTPS |
| `ctrl_relay.py` | native CTRL tunnel relay for `:6000` (16-byte framed handshake). | CTRL |
| `capture.sh` | HTTPS orchestrator: build shim, start mitmdump, launch the slicer. | HTTPS |
| `abi_tap/` | LD_PRELOAD `dlsym` interposition tap: captures the INPUT args the host passes into the genuine plugin (`PrintParams`, JSON commands, dev_id). See `abi_tap/README.md`. | ABI inputs |
| `import_flow.py` | any capture log -> anonymized `obn-wire-flow/v1` `flow.json`. | all |

### Input side vs output side

The wire MITM + relays record what the genuine plugin **emits** (→ fixture
`steps`). The **ABI tap** (`abi_tap/`) records what BambuStudio **hands the
plugin** (→ fixture `driver`), captured ground-truth instead of reconstructed by
inverting the wire output. `import_flow.py` merges an `abi_tap.jsonl` with the
wire logs: where a tapped input exists it is preferred (`meta.driver_source ==
"abi-captured"`), otherwise reconstruction is the fallback
(`"reconstructed"`). The tap is `dlsym`-interposition only — the genuine `.so` is
neither modified nor ptraced, so its VMProtect anti-debug and Studio's
cert/version/debug gates pass. Full design: `abi_tap/README.md`.

### Complete protocol coverage -> harness flows

Every OBN wire-flow type is now generatable from a genuine capture:

| Protocol | Transport | Capture tool | `import_flow.py --flow` | Harness driver |
|----------|-----------|--------------|--------------------------|----------------|
| HTTPS | `:443` TLS | `capture.sh` (shim + mitmdump) | `login` (+ generic `--match`) | HTTP mock |
| SSDP | `:2021` UDP | `ssdp_sniff.py` | `ssdp_discovery` | `obn::ssdp` parse + live listener |
| MQTT | `:8883` TLS | `mqtt_relay.py` | `device_command` | `MqttBrokerMock` |
| FTPS | `:990` TLS | `ftps_relay.py` | `storage_list` | `FtpsMock` |
| CTRL | `:6000` TLS | `ctrl_relay.py` (+ `ftps_relay.py`) | `ctrl_storage_list` | `NativeTunnelMock` + `FtpsMock` |

The non-HTTP flows emit a `driver` block (not recorded HTTP steps): the harness
feeds the captured raw material (SSDP packet, MQTT command_json, FTPS `listing`)
to the OSS code and asserts the parsed/emitted result. `start_print`'s FTPS
`STOR` leg (md5 of the uploaded 3mf) and its MQTT `project_file` leg reuse the
same relays; that flow also needs the sliced 3mf asset and is driven by the
harness's `body_builder`/`ftp_file_md5` path.

### Log format (one NDJSON line per request)

```json
{"method":"POST","path":"/v1/user-service/user/ticket/AJR7H7",
 "query":"/v1/user-service/user/ticket/AJR7H7",
 "headers":[["Host","api.bambulab.com"],["User-Agent","bambu_network_agent/02.07.00.50"], ...],
 "blen":19,"body":"{\"ticket\":\"AJR7H7\"}","status":200}
```

- `headers` preserves on-wire order (the harness asserts order).
- The addon masks the `Authorization` bearer token in the log; everything else
  is anonymized at import. Raw logs still land in a gitignored dir.
- Response bodies are not recorded (the request-matching harness does not need
  them; the fixture's `captures` are documented JSON-paths, not live values).

---

## 3. Capture -> fixture mapping (`import_flow.py`)

`import_flow.py LOG.jsonl --flow <flow> [--model M] [--channel C] [--os O] -o OUT`

| Fixture piece | Source |
|---------------|--------|
| `meta.os` | `X-BBL-OS-Type` (or `--os`) |
| `meta.network_plugin_version` | `bambu_network_agent/<ver>` in User-Agent |
| `meta.slicer_client_version` | `X-BBL-Client-Version` |
| `meta.channel` / `meta.printer_model` / `meta.flow` | `--channel` / `--model` / `--flow` (recognizer may default) |
| `identity_block.order` + `values` | header order of the most complete request in the flow; `X-BBL-Device-ID` -> `<dynamic:install-uuid>`, `Authorization` -> `<dynamic:Bearer access_token>` |
| `steps[].request.headers` flags | presence of the identity block, a client-id header, `Content-Type`, `Authorization`; non-identity headers -> `extra` |
| `steps[].request.body_json` | request body parsed as JSON (or `body_raw`), with `{{var}}` placeholders for recognized flows |
| `steps[].captures` | JSON-paths the flow feeds forward (e.g. `$.accessToken`) |

**Flow recognizers.** Each flow has a precise recognizer routed by `--flow`:

- `login` (HTTP) — POST `/v1/user-service/user/ticket/{{login_ticket}}` then GET
  `/v1/user-service/my/profile`, with var placeholders + captures.
- `ssdp_discovery` (SSDP) — picks a NOTIFY (by `--src` or `--model`), anonymizes
  the raw packet (Location IP, USN serial) while preserving header set/order/case
  (incl. the A1 uppercase-`HOST`/`:1900`/`DevSignal`/no-`NTS` variant), and emits
  the `driver.packet` + the `driver.expect` device-info the OSS parser must yield.
- `device_command` (MQTT, LAN or cloud) — from a publish to
  `device/<serial>/request` (the topic is identical on the LAN and cloud
  brokers, so a `mqtt_cloud_relay.py` capture imports through the same path); a
  `system`/`pushing` command imports `signed:false` (verbatim, e.g. cloud
  `ledctrl`), a `print` envelope (including the cloud-delivered `project_file`)
  imports `signed:true` with `command_json={"print":…}` (the harness re-signs
  RSA-SHA256 and cryptographically verifies). Anonymization additionally
  redacts credential/signature query params in a cloud `project_file` url
  (AWS/CloudFront presigned + Bambu `token`), keeping the url shape.
- `storage_list` (FTPS) — from a captured `LIST`; emits `driver.listing` (raw)
  + `driver.expect_files` (all regular files, name+size).
- `ctrl_storage_list` (CTRL) — same `listing` served over the FTPS bridge;
  `expect_files` filtered to `.3mf` model files (the `type=model` listing).
- `filament_manager` (HTTP) — GET `filament/config`, GET `my/filament/v2`
  (offset/limit), PUT `my/filament/v2` (templated body).
- `preset_sync` (HTTP) — GET `slicer/setting?version=&public=false` then the
  repeatable GET `slicer/setting/{{setting_id}}`.
- `preset_write` (HTTP) — POST `slicer/setting` (create), PATCH
  `slicer/setting/{{setting_id}}` (update), DELETE `slicer/setting/{{setting_id}}`.
- `cloud_print` (HTTP, `meta.flow=start_print`) — the full api.bambulab.com print
  pipeline (create_project, S3 config/main PUTs, notify/poll, get-upload,
  patch_project, create_task, poll_task). Reconstructs the `driver` PrintParams
  by inverting `build_task_body` on the captured `POST /my/task` body (amsMapping /
  amsMapping2 key-rename / amsDetailMapping / bed / cali flags). `--channel cloud`
  → `mode=cloud_file`; select the task with `--print-title` / `--dev`.
- `hybrid_print` (composite: HTTP + FTPS + MQTT, `meta.flow=start_print`,
  `channel=cloud_lan`) — the full pipeline PLUS the LAN legs: `driver.ftp_file_md5`
  from the captured FTPS `STOR`, and the MQTT `project_file` publish url. Pass the
  three logs (or a session dir) as multiple inputs.
- `lan_print` (composite: FTPS + MQTT, `channel=lan`) — pure LAN
  (`start_local_print`): FTPS `STOR` + MQTT `project_file` only, zero
  api.bambulab.com steps.

The print flows need the sliced 3mf under `assets/` (the api-scoped MITM does not
see the S3/FTPS upload bodies, only their md5); supply it from the slice, then the
harness uploads it and asserts the md5.

Any HTTP flow without a named recognizer uses a generic best-effort mode
(`--match <path-substring>`) that templatizes long numeric path segments.

### Composite (multi-log) import

`import_flow.py` accepts multiple capture logs or a session directory and merges
them by protocol:

```
import_flow.py http_all.jsonl ftps.jsonl mqtt.jsonl --flow hybrid_print \
    --channel cloud_lan --model h2s --dev <serial> -o flow.json
# or point at a directory of *.jsonl:
import_flow.py ./session-dir --flow hybrid_print --channel cloud_lan --model h2s
```

### Anonymization (applied to every emitted value)

| Real | Emitted |
|------|---------|
| IP address | `192.168.1.2` |
| LAN access code (8 hex) | `1234abcd` |
| printer serial | model-family prefix kept, remainder zeroed |
| cloud uid (`uid`/`uidStr`/`user_id`) | `1234567890` |
| email | `bob@test.com` |
| bearer token | `<dynamic:Bearer access_token>` |
| install/device UUID | `<dynamic:install-uuid>` |

Version strings (`02.07.00.50`) are preserved — the IP rule only matches real
dotted-quads (octets 0-255, no leading zeros), so it never mangles a version.

---

## 4. End-to-end workflow

### HTTPS (cloud REST)

```
tools/mitm-logging/capture.sh --studio ./build/src/bambu-studio   # log in, drive UI, quit
python3 tools/mitm-logging/import_flow.py mitm-captures/http_all.jsonl \
    --flow login --model account --channel cloud -o /tmp/flow.json
<obn>/build/wire_compliance_test /tmp/flow.json
```

### SSDP (fully passive; no printer credentials, no proxy)

```
python3 tools/mitm-logging/ssdp_sniff.py --seconds 20 --out ssdp.jsonl   # sniff real NOTIFYs
python3 tools/mitm-logging/import_flow.py ssdp.jsonl --flow ssdp_discovery --model a1 -o /tmp/ssdp.json
<obn>/build/wire_compliance_test /tmp/ssdp.json
```

### MQTT / FTPS / CTRL (LAN; access code only, no Bambu account)

Start the relay for the target printer, point the plugin's traffic at it via the
shim (`REDIRECT_8883/990/6000=<relay port>`, one printer at a time), drive the
flow, then import. Example for FTPS storage listing:

```
python3 tools/mitm-logging/ftps_relay.py --printer <ip> --dev <serial> \
    --listen-port 9990 --out ftps.jsonl &
LD_PRELOAD=tools/mitm-logging/mitm_redirect.so REDIRECT_990=9990 ./build/src/bambu-studio  # open Device->Storage
python3 tools/mitm-logging/import_flow.py ftps.jsonl --flow storage_list --model <model> -o /tmp/sl.json
<obn>/build/wire_compliance_test /tmp/sl.json
```

MQTT (`mqtt_relay.py --broker <ip> --listen-port 8883`, `--flow device_command`)
and CTRL (`ctrl_relay.py --printer <ip> --listen-port 6000`, then
`--flow ctrl_storage_list` reusing the FTPS listing) follow the same pattern.
Point-and-import against the OBN tree + `ctest` as with HTTPS.

### Reading a failure as "OBN diverges from genuine"

The harness drives the OSS plugin for `meta.flow`, records every request OSS
emits, and asserts it against `steps[]`. A pass means OSS matches the genuine
trace. A failure names the first divergence, e.g.:

```
FAIL: [exchange_ticket] header X-BBL-Language out of JA4H order
FAIL: [get_profile] missing Content-Type
```

Each line is a concrete field where the OSS plugin's wire output differs from
the genuine trace you captured — the exact thing to fix in OBN.

---

## 5. Verification status

All five protocols verified on Linux; each generated fixture is accepted by
`wire_compliance_test` (`WIRE-COMPLIANCE OK`):

| Protocol / flow | Verified against | Result |
|-----------------|------------------|--------|
| HTTPS `login` | genuine capture (`http_all.jsonl`) | fixture passes; perturbation reports the concrete diff |
| HTTPS `filament_manager` | genuine capture | harness OK (3 requests) |
| HTTPS `preset_sync` | genuine capture | harness OK |
| HTTPS `preset_write` | genuine capture | harness OK (3 requests) |
| HTTPS `cloud_print` (start_print, cloud_file) | genuine capture + sliced 3mf assets | harness OK (10 requests; create_task cloud_file body-builder) |
| Composite `hybrid_print` (start_print, lan_file) | genuine HTTP + **live** FTPS `STOR` md5 + replay MQTT `project_file` | `drive_lan_start_print` OK (create_task lan_file + STOR md5 match + project_file ftp:// url) |
| Composite `lan_print` (pure LAN) | genuine FTPS `STOR` + replay MQTT | **structural only** — no harness `lan` driver yet (see below) |
| SSDP `ssdp_discovery` (a1 + h2s) | **live** real printer NOTIFY broadcasts on `:2021` | parse + live UDP listener pass |
| MQTT `device_command` (LAN) | **live** relay to a real printer `:8883` (CONNACK + PUBACK from the printer) | `MqttBrokerMock` matches |
| cloud MQTT `device_command` | shim redirect reaches the relay live (plugin `us.mqtt.bambulab.com` connection lands on `:9883`); relay TLS-terminate + bidirectional parse + forward + real-broker upstream TLS 1.3 proven by loopback; importer `ledctrl`/`project_file` fixtures pass | `MqttBrokerMock` matches; **the plugin's cloud MQTT is certificate-pinned (embedded CA inside libbambu_networking.so's own VMProtect-packed OpenSSL — confirmed by connect() backtrace, not BambuSource) — the live session cannot be TLS-MITM'd without an in-plugin code patch; system-store install + full CA-file redirect + BambuSource symbol interposition all rejected** |
| FTPS `storage_list` | **live** relay to a real printer `:990` (real directory LIST, TLS session reuse) | `FtpsMock` parses all files |
| CTRL `ctrl_storage_list` | **live** `:6000` LOGIN handshake against a real printer + full harness `NativeTunnelMock`+`FtpsMock` run | handshake accepted; harness passes |

**`lan_print` — remaining obn-repo piece.** The OBN harness dispatches
`meta.flow=start_print` to the cloud/cloud_lan drivers only; there is no pure
`lan` (`start_local_print` → `run_local_print_job`) driver. Running a `lan`
fixture today falls through to the cloud driver and reports a **vacuous** OK
(it emits `create_project` and finds no HTTP steps to check — it does not
exercise the FTPS `STOR` / MQTT `project_file` legs). The fixture the importer
produces is structurally complete (STOR step with `{{ftp_file_md5}}` + MQTT
`project_file` step + `driver`); adding a `lan` driver in the obn repo
(analogous to `drive_lan_start_print` but with no api pipeline) is the missing
piece. This tool does not modify the obn repo.

**Print-flow assets.** `cloud_print` / `hybrid_print` need the sliced 3mf under
the fixture's `assets/` (the api-scoped MITM never sees the S3/FTPS upload
bodies, only their md5). For verification the box20 slice from the existing
`cloud/h2s/start_print` fixture was used (its md5 matches the live FTPS `STOR`
captured through the relay: `c243a8a7…`).

**What "live" means per protocol:**

- **SSDP** — fully live and automated: real printers broadcast every ~5s, no
  credentials, no proxy. Captured, imported, and passed with no manual step.
- **MQTT / FTPS / CTRL** — the relay logic (TLS-terminate, protocol parse, log,
  forward) was smoke-tested against real printers using only the LAN access code
  (no Bambu account): FTPS returned a real listing, MQTT round-tripped a
  `pushall`, CTRL completed the `:6000` LOGIN handshake. The credential/personal
  material is redacted or anonymized; captures stay in the gitignored runtime dir.
- **CTRL SETUP payload** — the LOGIN handshake is live-verified; the exact
  genuine SETUP JSON (mtype 12290 fields) that yields a `result:0` reply comes
  from a real plugin capture. The harness's `NativeTunnelMock` models the full
  handshake, so `ctrl_storage_list` passes end-to-end today.

**Manual step (one, unavoidable):** capturing the *genuine plugin's own* traffic
for MQTT/FTPS/CTRL/HTTPS needs the user's Bambu login + GUI to drive the flow.
The relays and shim are proven; only the human-driven trigger is manual. SSDP has
no manual step.

**Remaining / partial:**

- **`lan_print` harness driver** — the fixture is produced and structurally
  verified; a pure-`lan` driver in the obn repo is the missing verification piece
  (see the verification table above).
- **S3 presigned PUTs** — the 3mf upload bodies go to short-lived S3 URLs on a
  different host; the api-scoped MITM records only their md5 (enough for the
  fixture). Scope the shim to those hosts to capture the bodies themselves.
- **MQTT `project_file` capture** — for `hybrid_print`/`lan_print` a *live*
  project_file publish would start a print, so the MQTT `project_file` step url
  is populated from a replay record; the FTPS `STOR` md5 (the load-bearing field
  the harness asserts) is captured live.
- Captures containing a user's real file names / device state are used for
  verification only and are **not** committed (only the tools land in-repo).

---

## 6. Cross-platform

- **macOS** — same design; `DYLD_INSERT_LIBRARIES` + an interpose table replaces
  `LD_PRELOAD`, or use `mitmproxy` transparent mode with `pf`. The addon and
  `import_flow.py` are unchanged.
- **Windows** — the plugin is a DLL using WinHTTP/schannel or bundled OpenSSL;
  redirect via a hosts entry / WinDivert to a local mitmdump and add the CA to
  the trust the plugin uses. The log format and importer are unchanged.

## Security

Raw captures under `mitm-captures/` and the mitmproxy CA private key
(`~/.mitmproxy/`) contain live tokens and personal identifiers. Both are
gitignored / outside the repo and **must never be committed**. Only anonymized
fixtures produced by `import_flow.py` are committed. Never commit the slicer
signing key or any baked key value.
