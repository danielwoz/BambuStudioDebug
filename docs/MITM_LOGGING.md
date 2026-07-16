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

---

## 2. Components (`tools/mitm-logging/`)

| File | Role | Protocol |
|------|------|----------|
| `mitm_redirect.c`, `build_redirect.sh` | LD_PRELOAD transport shim; steers `:443` (api.bambulab.com) and, when the paired `REDIRECT_8883/990/6000` env is set, the LAN transports to local relays. | all |
| `wire_addon.py` | mitmdump addon; one NDJSON line per REST request. | HTTPS |
| `ssdp_sniff.py` | passive UDP `:2021` sniffer for printer NOTIFY broadcasts (no TLS). | SSDP |
| `mqtt_relay.py` | TLS-terminating MQTT 3.1.1 relay for `:8883` (LAN printer / cloud broker). | MQTT |
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
- `device_command` (MQTT) — from a publish to `device/<serial>/request`; a
  `system`/`pushing` command imports `signed:false` (verbatim), a `print`
  envelope imports `signed:true` with `command_json={"print":…}` (the harness
  re-signs RSA-SHA256 and cryptographically verifies).
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
| MQTT `device_command` | **live** relay to a real printer `:8883` (CONNACK + PUBACK from the printer) | `MqttBrokerMock` matches |
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
