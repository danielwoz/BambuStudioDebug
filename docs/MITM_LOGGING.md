# MITM wire-logging (`obn-wire-flow/v1` capture)

BambuStudioDebug is an instrumented fork of BambuStudio whose purpose is to
record every network interaction the slicer performs, in the exact schema
consumed by the wire-compliance harness (`obn-wire-flow/v1`). The captured
traces become golden fixtures: the contract an OSS network library must
reproduce message-for-message (method / path / query / header set+order /
body shape).

This document describes **where** the logging sits, **how** each intercepted
interaction maps to a fixture, the **runtime capture directory** and the
**anonymize-on-export** step, and how it plugs into the build. It is
**Linux-first**; macOS and Windows are covered in *Cross-platform* at the end.

Target build: release tag **`v02.07.00.55`** (this branch is based on it).
That version reports `X-BBL-Client-Version: 02.07.00.55` on the wire, which is
exactly the `slicer_client_version` of the existing fixtures under
`obn-cloud-header-order/tests/wire-fixtures/linux/02.07.00.50/…`, so captures
from this build drop straight into the current fixture tree. Master
(`02.08.01.55`) is also buildable but would emit a different client-version
header — a new fixture leaf, not a match for the current ones.

---

## 1. Where the MITM sits — decision

**The recorder lives inside the OSS `obn` network plugin, not in a separate TLS
proxy and not in BambuStudio core.** Rationale:

- BambuStudio does **no networking itself**. All cloud REST, LAN MQTT, FTPS,
  SSDP and the libBambuSource CTRL/camera channels are delegated across a C ABI
  (`bambu_network_*` / `Bambu_*`) to a dynamically-loaded plugin
  (`src/slic3r/Utils/NetworkAgent.cpp` `dlopen`s
  `libbambu_networking.so`). A tap in NetworkAgent would only see **ABI-level
  arguments** (a `BBL::PrintParams`, a device id) — never the wire bytes,
  header order, or exact paths the fixtures assert.
- The `obn` plugin (`/mnt/cephfs/ssd/obn-cloud-header-order`) is a from-scratch
  OSS implementation of that same ABI that **already intercepts every network
  boundary** and already knows the genuine wire format (that is its whole
  reason to exist). Every request is funnelled through a small number of choke
  points. Adding a logging layer there gives us the true wire view for free.
- A separate MITM TLS proxy (mitmproxy / a CA-injection box) would re-solve
  TLS termination, certificate pinning on the LAN channel, and the proprietary
  libBambuSource `:6000` tunnel — all of which `obn` already handles. It would
  also miss the header *ordering* that Cloudflare fingerprints (a proxy
  re-serialises headers).

So: **BambuStudioDebug is configured to load the `obn` plugin, and `obn` gains
a thin "wire recorder" that emits NDJSON at each choke point.** The recorder
source is vendored in *this* repo (`tools/mitm-logging/recorder/`) so both
sides can share one implementation; `obn` includes it at its choke points.

### Choke points in `obn` (one recorder call each)

| Boundary | `obn` source / function | Recorder call |
|----------|-------------------------|---------------|
| Cloud REST (all api.bambulab.com + S3 PUTs) | `src/http_client.cpp` `obn::http::perform()` | `record_http()` — after headers are assembled in wire order, before/after `curl_easy_perform` |
| LAN MQTT (device control, publishes + messages) | `src/mqtt_client.cpp` `Client::publish()` / `s_on_message` | `record_mqtt(dir, topic, payload, qos, retain)` |
| FTPS upload / listing | `src/ftps.cpp` `Client::store()` (STOR) / `Client::list_entries()` (LIST) | `record_ftps(op, path, size, md5)` |
| SSDP discovery | `src/ssdp.cpp` `parse()` / `Discovery` | `record_ssdp(dir, raw)` |
| libBambuSource CTRL channel | `src/tunnel_local.cpp` cmdtype envelopes | `record_ctrl(dir, cmdtype, json)` |

`http_client.cpp` already has an `OBN_HTTP_TRACE=1` verbose mode and a
structured `OBN_DEBUG("http …")` line; the recorder is the structured,
machine-readable sibling of that, gated by its own env so it stays off by
default.

### Optional secondary tap (in this repo, `BBL_MITM_LOGGING`)

For completeness the fork also carries a build option `BBL_MITM_LOGGING`
(default `OFF`) that compiles the recorder into the slicer itself for an
**ABI-level** trace (what Studio hands the plugin, before wire encoding). This
is a diagnostic cross-check, **not** the fixture source — the wire fixtures
come from the `obn` choke points above.

---

## 2. Interaction → fixture mapping

The recorder emits a flat **NDJSON event stream** (one JSON object per line)
into the runtime capture dir. A post-processing step
(`tools/mitm-logging/export_fixtures.py`) folds a session's events into one
`flow.json` per `obn-wire-flow/v1` leaf and anonymises them.

Fixture leaf path (from `FORMAT.md`):

```
<os>/<network_plugin_version>/<channel>/<printer_model>/<flow>/flow.json
```

- `os` — `linux` for this build.
- `network_plugin_version` — the `bambu_network_agent/<ver>` the `obn` build
  reports (its `OBN_VERSION`, e.g. `02.07.00.50`).
- `channel` — `cloud` | `cloud_lan` | `lan`, inferred from the recorded event
  set (presence of the `ftp://`-placeholder PATCH + FTPS STOR ⇒ `cloud_lan`;
  pure S3 download, no LAN legs ⇒ `cloud`; no api.bambulab.com at all ⇒ `lan`).
- `printer_model` — `account` for user/preset/filament flows; `h2s`/`h2d`/`a1`
  for device flows (from the driver / dev serial prefix).
- `flow` — the UI action the session was driven for (operator picks it when
  launching a capture; see the run script's `BBL_MITM_FLOW`).

### Per-event → `steps[]` mapping

| Recorder event | `obn-wire-flow/v1` element |
|----------------|---------------------------|
| `http` | one `steps[]` entry: `protocol:"http"`, `request.method/host/path`, `request.query`, `request.headers` (the recorded ordered header list is diffed against the flow's `identity_block.order` to set the `block`/`client_id`/`content_type`/`authorization` flags + `extra`), `request.body_json`/`body_raw`, `expect.status` |
| `mqtt` (publish to `device/<serial>/request`) | `steps[]` with `protocol:"mqtt"`, `channel_only` where relevant; body is the command envelope (for signed `print` commands the `sign_string` is captured for the harness to *verify*, never the key) |
| `ftps` STOR | the `cloud_lan`-only upload leg; `ftp_file_md5` in the fixture `driver` block |
| `ftps` LIST | `storage_list` flow: raw listing bytes → `driver.listing` + `expect_files` |
| `ssdp` | `ssdp_discovery` flow: raw NOTIFY → parsed device-info JSON |
| `ctrl` | `ctrl_storage_list` flow: cmdtype envelope sequence |

The first line of every session is a `meta` event carrying
`os / network_plugin_version / slicer_client_version / channel / printer_model
/ flow`, which becomes the fixture `meta{}` block. `identity_block` and `vars`
are filled by the exporter from the observed headers and the values it must
treat as dynamic (tokens, uuids, timestamps, presigned URLs).

The exporter emits a **skeleton** `flow.json` that a human reviews against the
existing hand-authored fixtures before it is committed — it is a capture aid,
not an auto-committer.

---

## 3. Runtime capture dir + anonymize-on-export

- Raw captures are written to **`$BBL_MITM_CAPTURE_DIR`** (default
  `./mitm-captures/` at the repo root). This directory is **gitignored**
  (`.gitignore` → `mitm-captures/`). Raw captures contain live tokens, real
  uid/email/serials/IPs/access codes and MUST NOT be committed.
- Filenames: `session-<UTC-timestamp>-<flow>.ndjson`.
- **Nothing** in the capture dir is safe to commit as-is.
- `export_fixtures.py` performs the **anonymize-on-export** step required before
  any fixture derived from a capture is committed:

  | Field | Anonymized to |
  |-------|---------------|
  | IP addresses | `192.168.1.2` |
  | access codes | `1234abcd` |
  | serials | model prefix kept, rest zeroed (e.g. `094…` → `09400000000000`) |
  | uid | `1234567890` |
  | email | `bob@test.com` |
  | bearer / access / refresh tokens | replaced with `<dynamic:…>` markers (they are `vars`, matched by kind not literal) |
  | presigned S3 URLs | `host:"<presigned>"`, query dropped |

  Tokens, device-ids, timestamps and presigned URLs are turned into
  `obn-wire-flow/v1` `vars` with `kind: session|generated|from_response`, so the
  harness matches them by kind, never by the captured secret value.

**Never committed, ever:** the extracted slicer signing key `d` /
`slicer_key.pem`, any baked key value, `BambuNetworkEngine.conf`, cloud auth
tokens, or raw captures with personal identifiers.

---

## 4. Build integration

### 4.1 The plugin (primary — where the wire is seen)

BambuStudioDebug loads the `obn` plugin instead of the proprietary one. Build
`obn` with the recorder enabled and run the slicer pointed at it:

```
# build obn with wire recording compiled in (adds tools/mitm-logging/recorder)
cd /mnt/cephfs/ssd/obn-cloud-header-order
./configure --with-version=02.07.00.50 --enable-wire-record   # (obn-side flag, see run script)
make && make install     # installs libbambu_networking_02.07.00.50.so into the slicer plugin dir

# then launch the slicer with capture on
tools/mitm-logging/run_with_logging.sh --flow start_print --model h2s
```

`run_with_logging.sh` sets `BBL_MITM_CAPTURE_DIR`, `BBL_MITM_FLOW`,
`OBN_WIRE_RECORD=1` (the env the `obn` recorder honours) and launches the
built `bambu-studio` binary. The obn-side `--enable-wire-record` /
`OBN_WIRE_RECORD` wiring is the remaining obn change (Phase 2 below); the
recorder library itself already lives here and compiles standalone.

### 4.2 The slicer (secondary — ABI-level cross-check)

Top-level CMake option, default OFF:

```
cmake -S . -B build -DBBL_MITM_LOGGING=ON …
```

When ON it defines `BBL_MITM_LOGGING` and adds
`tools/mitm-logging/recorder` to the include path so a NetworkAgent-level tap
can call the same recorder. This is intentionally minimal for milestone 1 —
the tap call-sites in `NetworkAgent.cpp` are Phase 2.

---

## 5. Cross-platform

- **Linux** — implemented target of this milestone (recorder + build option +
  run/export tooling). The `X-BBL-OS-*` identity block is the `linux` variant.
- **macOS — deferred.** Same plugin-load model (`.dylib`), different
  `X-BBL-OS-Type: macos` identity and different config paths; it produces a new
  `macos/…` fixture tree. Not scaffolded here.
- **Windows — deferred, and additionally depends on the BambuSlicerKeySaver
  watchdogs** (`/mnt/cephfs/ssd/slicer_key_saver/BambuSlicerKeySaver`). On
  Windows the proprietary stack is packed (VMProtect) and the plugin/source
  libraries need the keysaver watchdogs to reach a running, interceptable
  state:
  - the **conf-key / slicer-key saver** watchdog (recovers the
    `bambu_networking` conf + slicer key so an `obn`-style plugin can be
    substituted at all), and
  - the **process/inject watchdog** that keeps the substituted plugin loaded
    past the module signature check.

  Until those are wired into a Windows BambuStudioDebug build, Windows capture
  is out of scope. The `X-BBL-OS-Type: windows` identity + `windows/…` fixture
  tree is the eventual deliverable.

---

## 6. Status (milestone 1)

- Fork + all upstream tags: **done**.
- Recorder library (`tools/mitm-logging/recorder/`): **compiles standalone**
  (see its CMake + smoke target).
- `BBL_MITM_LOGGING` build option + `.gitignore` capture dir: **done**.
- Run + export/anonymize scripts: **scaffolded** (export emits a review
  skeleton; not yet exercised against a live capture).
- `obn`-side choke-point calls + `OBN_WIRE_RECORD` wiring: **Phase 2, not done**.
- NetworkAgent ABI-level tap call-sites: **Phase 2, not done**.
- macOS / Windows: **deferred** (Windows blocked on keysaver watchdogs).
</invoke>
