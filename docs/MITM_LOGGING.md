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

| File | Role |
|------|------|
| `mitm_redirect.c`, `build_redirect.sh` | LD_PRELOAD transport shim (above). |
| `wire_addon.py` | mitmdump addon; appends one NDJSON line per request. |
| `capture.sh` | orchestrator: build shim, start mitmdump, launch the slicer. |
| `import_flow.py` | log -> anonymized `obn-wire-flow/v1` `flow.json`. |

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

**Flow recognizers.** `login` has a precise recognizer that matches the harness
driver exactly (POST `/v1/user-service/user/ticket/{{login_ticket}}` then GET
`/v1/user-service/my/profile`, with the right var placeholders and captures).
Other flows use a generic best-effort mode (`--match <path-substring>`) that
turns each matching request into a step and templatizes long numeric path
segments (task/design ids) into vars — a starting point to refine by hand
against `FORMAT.md`.

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

```
# 1. capture with the genuine plugin (one manual step: log in + drive the UI)
tools/mitm-logging/capture.sh --studio ./build/src/bambu-studio
#    -> mitm-captures/http_all.jsonl   (gitignored)

# 2. import a flow -> anonymized fixture
python3 tools/mitm-logging/import_flow.py mitm-captures/http_all.jsonl \
    --flow login --model account --channel cloud -o /tmp/flow.json

# 3. place it in the OBN fixture tree and run the harness
cp /tmp/flow.json \
  <obn>/tests/wire-fixtures/linux/02.07.00.50/cloud/account/login/flow.json
ctest --test-dir <obn>/build -R wire_ --output-on-failure
#    or directly:
<obn>/build/wire_compliance_test /tmp/flow.json
```

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

Verified end-to-end on Linux against a genuine capture
(`bambu_network_agent/02.07.00.50`, slicer `02.07.00.55`):

- `import_flow.py --flow login` on a real genuine log produces a fixture whose
  structure matches the hand-authored login fixture.
- `wire_compliance_test <fixture>` **passes** (OSS matches genuine for login).
- Perturbing the fixture (e.g. swapping two identity headers) makes the harness
  report the concrete divergence — proving the match/diff path both ways.

**Working:** HTTPS (`api.bambulab.com`) capture, login import, harness
integration, anonymization.

**Manual step:** the live capture itself needs the user's Bambu login and GUI
interaction — it cannot be automated.

**Extensions (schema ready, transport not yet wired):**

- **MQTT (8883)** — LAN device control. The redirect shim only scopes `:443`;
  add an `:8883` sentinel + an MQTT-aware proxy (e.g. mitmproxy's raw TCP mode
  or a small broker relay) and emit `protocol:"mqtt"` steps. The fixture schema
  already carries MQTT steps.
- **FTPS (990)** — implicit-FTPS 3mf upload. Needs an FTPS-aware relay to log
  `STOR`/`LIST`; the harness already models this with `FtpsMock`.
- **S3 presigned PUTs** — the 3mf upload bodies go to short-lived S3 URLs on a
  different host; scope the shim to those hosts or record them as
  `host:"<presigned>"` steps.

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
