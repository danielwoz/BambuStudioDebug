# Cloud-MQTT pin-patch death: TAMPER verdict

## Question

After the cloud-MQTT certificate pin is defeated with `pin_patch` (NOP-6 the
`ssl_verify_cert_chain` result gate at plugin offset `0x3f91db`), the cloud MQTT
session connects through `mqtt_cloud_relay.py` and real cloud wire is captured —
but BambuStudio then dies shortly after (`terminate called without an active
exception`, black screen), before the GUI can be driven. Is that death:

- **(T) a delayed / second-stage TAMPER response** — the genuine plugin detecting
  the patch and self-destructing; or
- **(E) an unrelated ENVIRONMENTAL crash** — headless wx / GTK / network?

## Method

A death-catcher was preloaded into every run: `tools/mitm-logging/death_trace.c`
installs `std::set_terminate` plus `SIGABRT/SEGV/ILL/BUS/TRAP` handlers that, at
the instant of death, capture a `backtrace()` and resolve each frame with
`dladdr` to `<module>+<offset>`, and snapshot `/proc/self/maps`. The decisive
signal is **which module owns the frame that calls `std::terminate`**: inside
`libbambu_networking.so` → tamper; inside wx / GTK / libstdc++ / libc / network
→ environmental. No ptrace / gdb-attach was used (plugin is anti-debug).

Five controlled runs isolate patch vs. relay vs. environment. All were headless
(Xvfb :99 + openbox), logged in, using the genuine plugin
(`02.07.01.51`, md5 `f6f8a47b…`) with `app.ignore_module_cert=true`. The patch
used the `PROCMEM` write method (`/proc/self/mem`, **no `mprotect`** — so the
page's permissions are never changed; only its *content* changes).

## Control matrix

| # | Scenario | Patch | Relay/redirect | Outcome | Terminating frame |
|---|----------|:-----:|:--------------:|---------|-------------------|
| A | Baseline | no | no | **SURVIVED 300s**, healthy GUI, logged in, online models loaded | — (no death) |
| C | Relay, no patch | no | yes | **SURVIVED 220s**; 38× `unknown_ca`, cloud never connects, process fine | — (no death) |
| B | Patch, no relay | yes | no | **DIED ~13s after patch** (patched 01:24:47, terminate 01:25:00) | **`libbambu_networking.so+0x2f2980`** |
| D | Patch + relay (full repro) | yes | yes | cloud TLS **established**, 11 wire lines captured, **DIED ~14s after patch** | **`libbambu_networking.so+0x2f2980`** (identical) |
| E | Patch + relay + `tamper_park` | yes | yes | terminate parked, but main thread **SIGSEGV ~1s later** | terminate: plugin; segv: wx/webview (no plugin frame) |
| F | Patch + `PIN_PATCH_RESTORE_MS=5000` + relay | yes (restored) | yes | **SURVIVED** (37s+ past window, healthy GUI); cloud not captured this run (window/handshake miss) | — (no death) |

### The terminating backtrace (B and D — byte-identical plugin offsets)

```
std::terminate ENTERED  (no active exception — direct terminate)
  #01 libstdc++.so.6+0xae20c            std::terminate
  #02 libstdc++.so.6+0xae277
  #03 libbambu_networking.so+0x2f2980   <-- CALLS std::terminate (the checker)
  #04 libc.so.6+0x45495
  #05 libc.so.6+0x45610  (on_exit region)
  #06 libbambu_networking.so+0x250f50   <-- plugin worker function
  #07 libbambu_networking.so+0x5584f5   <-- plugin worker-thread entry
  #08 libc.so.6+0x94ac3  (start_thread)
  #09 libc.so.6+0x1268d0 (clone)
```

The offsets `+0x2f2980`, `+0x250f50`, `+0x5584f5` are **identical across B (no
relay) and D (relay)** despite different ASLR bases — a deterministic code site,
running on a **plugin-spawned worker thread** (not the main thread).

## Verdict: TAMPER (decisive)

1. **Baseline survives.** Control A (genuine plugin, no patch, no relay) runs
   healthy for 300s. The death is not a passive environmental timer. (Note:
   `use_count = 4`, the line that preceded the original death, also appears in
   A's log — it is a benign periodic log line, not a death precursor.)
2. **The cloud path alone does not kill.** Control C (relay, no patch) survives
   220s; the pinned TLS simply fails (`unknown_ca`) and the process lives.
3. **The patch alone kills — with no cloud interception at all.** Control B
   (patch, **no relay/redirect**) dies ~13s after the patch is written. The only
   variable is the modified code byte(s).
4. **The terminating frame is inside the plugin**, on a plugin worker thread, at
   a deterministic offset. It is the plugin's own code invoking `std::terminate`.
5. The write used `/proc/self/mem` (no permission change), so the trigger is a
   **content re-scan** of the plugin's own code, not a page-permission watch. No
   write-back of the NOP was observed before death (the checker does not repair
   the code — it self-terminates).

**Mechanism:** a second, *delayed* integrity check. A plugin worker thread
periodically (or on next-use, ~13–15s cadence observed) re-hashes the plugin's
code region, detects the NOP where the `jle` was, and self-destructs by calling
`std::terminate` from `libbambu_networking.so+0x2f2980`. This is distinct from
the one-shot **init-time** content check the prior work already characterised
(patching at startup crashes in ~1s); `PIN_PATCH_DELAY_MS=60000` clears that
first check but not this later, recurring one.

## Defeat

Because the self-destruct routes through `std::terminate` — a process-wide,
overridable handler (that is exactly how `death_trace` observed it) — it can be
neutralised in-process without touching the checker itself.
`tools/mitm-logging/tamper_park.c` installs a terminate handler that, when the
entering frame lies inside `libbambu_networking.so`, **parks that one thread
forever** (never returns, never aborts) instead of letting the process die; a
terminate originating outside the plugin is passed through to the normal abort
path so genuine app faults are not masked (verified).

**Control E (patch + relay + `tamper_park`):** the tamper `std::terminate` was
intercepted and its thread parked (`plugin_caller=1`, same `+0x2f2980` offsets) —
so the self-destruct terminate itself IS interceptable. But ~0.8s later the
**main thread** took a `SIGSEGV` whose backtrace has **no plugin frame**
(`plugin_frame=0`) — it faults in JavaScriptCoreGTK / wxWidgets / glib main-loop
code. Baseline A ran that same webview for 300s without faulting, so this crash
is collateral fallout of the neutralised self-destruct (the checker leaves shared
state inconsistent / mid-terminate), not a baseline environmental bug. **Parking
the terminate is therefore necessary but not sufficient** — the process still
dies, just elsewhere and ~1s later.

**Control F (patch + `PIN_PATCH_RESTORE_MS` + relay):** because the check is a
*stateless content re-scan* (Controls B/D), restoring the original `jle` bytes a
few seconds after the handshake completes — before the ~13s scan — lets the scan
find pristine code. The cloud session, already established, persists.

**Result: the process SURVIVES.** Patched 01:41:33, original bytes restored
01:41:39, and at 01:42:10 (37s post-patch, far past the ~13s self-destruct) the
GUI is alive, healthy, and logged in — `death_bt` clean, no terminate, no
SIGSEGV. This confirms the check is a **stateless content re-scan with no latched
"already tampered" flag**: pristine code at scan time = no self-destruct. The
tamper is defeated.

Caveat for *capture*: in this run the plugin's cloud-connect retry did not land a
TLS handshake inside the 5 s pre-restore window, so the cloud leg stayed
`unknown_ca` (graceful "failed to connect to cloud device server" dialog, exactly
like Control C) and no wire was logged. A stable capture therefore needs the
restore to fire *after* a handshake actually completes but *before* ~13 s — a
narrow but workable race. Control D shows the handshake completes ~1–2 s after
the patch when a retry aligns; so the robust recipe is: keep the patch up, watch
`mqtt_cloud_relay` for the `established` line (or the first cloud record), then
restore within a second or two of that — comfortably inside the self-destruct
budget. Event-driven restore (vs. the fixed `PIN_PATCH_RESTORE_MS` timer used
here) closes the gap.

### Recommended path to a stable cloud capture

Control F already gives a working defeat (`pin_patch` restore mode). To also
capture the cloud wire reliably, make the restore **event-driven** rather than a
fixed timer: keep the pin down until `mqtt_cloud_relay` logs `established` (or the
first cloud record arrives), then restore the original bytes within ~1–2 s — still
inside the ~13 s self-destruct budget. That guarantees the handshake completes
(cloud session up, wire flowing) *and* the code is pristine before the re-scan.

Sturdier alternatives, in increasing effort: patch the terminate call site
(`+0x2f2980`) or the comparison feeding it so the check always passes; or locate
and freeze the checker before it scans. The checker function is `+0x250f50`,
reached from thread entry `+0x5584f5` — the starting point for static analysis of
the hash routine.

## Reproduction

```
# genuine plugin swapped into ~/.config/BambuStudio/plugins, ignore_module_cert=true
tools/mitm-logging/build_pin_bypass.sh            # builds the .so diagnostics
DISPLAY=:99 \
LD_PRELOAD=death_trace.so:pin_patch.so \
  PIN_PATCH_DELAY_MS=60000 PIN_PATCH_PROCMEM=1 \
  DEATH_TRACE_OUT=/tmp/death_bt.log \
  bambu-studio            # dies ~13s after the patch arms; frame #03 in the plugin
```

Add `tamper_park.so` at the front of `LD_PRELOAD` to neutralise the self-destruct.

## Event-driven restore — STABLE cloud capture (the shipped path)

Control F's fixed `PIN_PATCH_RESTORE_MS` timer worked as a *defeat* but was racy
for *capture* (its 5 s timer could restore before the handshake landed, or — with
the loop counting iterations rather than wall time — drift past the ~13 s scan and
self-destruct anyway). Both problems are removed by driving the restore off the
actual handshake:

- **`mqtt_cloud_relay.py`** writes a sentinel file (`--established-sentinel`,
  e.g. `/tmp/bbl_capture/cloud_established`) atomically the instant the plugin's
  cloud CONNECT traverses the relay (upstream TLS established + client CONNECT
  seen) — i.e. the moment the cloud-broker handshake genuinely completed.
- **`pin_patch.c` `PIN_PATCH_RESTORE_ON=<sentinel>`** keeps the pin DOWN through
  any pre-establishment `unknown_ca` retry, then restores the pristine `jle` as
  soon as the sentinel appears (`PIN_PATCH_RESTORE_SETTLE_MS` optionally dwells a
  few seconds first), with a hard `PIN_PATCH_RESTORE_MAX_MS` fallback so the
  restore ALWAYS precedes the scan. Restore timing is now **wall-clock**
  (`CLOCK_MONOTONIC`), not loop-iteration counted — the per-pass memmem over the
  plugin's ~30 MB unpacked span makes iteration timers drift badly (a fixed-timer
  full-window run measured 11 000 "loop ms" but elapsed >13 s wall and hit the
  self-destruct; the event-driven sentinel path is immune because it fires on the
  real file event).

**Result (verified live, genuine plugin 02.07.01.51, Studio 02.07.01.57 headless,
account logged in):** repeated runs establish the cloud session through the relay
and SURVIVE well past the scan. Representative timing:

```
patched          15:50:10
established       15:50:17  (relay: upstream TLS + CONNECT -> sentinel)
RESTORED          15:50:17  (trigger=sentinel, +4.6 s)  -- another run +6.0 s
scan survived     15:51:02+ (52 s post-patch; death_bt clean, no terminate)
```

The captured wire is a real bidirectional cloud session for the H2S:
`CONNECT` (username=cloud uid, redacted), `SUBSCRIBE user/<uid>/request` +
`device/<serial>/report`, and publishes to `device/<serial>/request`
(`pushall`, `get_version`, `get_access_code`, `app_cert_install`) with the
matching `device/<serial>/report` pushes (`push_status` incl. a full ~9 KB state
dump, then live deltas). The pin is pristine before the re-scan, so the process
lives and the session persists.

### Residual gap — GUI device stays "offline", so ledctrl can't be GUI-driven

Capturing a *specific interactive* command (the chamber-light `ledctrl`) also
needs Studio's Device→Control panel to be enabled, which is gated on the machine
showing **online**. Under the MITM it never does: the pin blocks Studio's FIRST
cloud handshake at startup, Studio latches a failed "server connection" (orange
`Failed to connect to the server` banner, red wifi-off on the device), and the
later pin-down reconnect — though it establishes the raw MQTT session that the
relay captures — does not clear that latched UI state. The device temperatures
never populate and the Lamp button stays disabled, across every reconnect nudge
tried (Device-tab entry, machine re-select, server-reconnect banner, all during
and after pin-down). So the light round-trip specifically could not be driven;
the other device commands above ARE captured on the real cloud wire. Closing this
gap needs the FIRST cloud connection to succeed cleanly (pin down before Studio's
initial connect, which the init-integrity check forbids for ~60 s) or a
plugin-side connection-state fix beyond the transport MITM.

## UI-online residual — timeline, the exit(0) checker, and the device-leg wall

A dedicated pass measured the timeline precisely and pushed the UI-online residual
much further. Key corrections and new findings (genuine plugin `f6f8a47b`,
02.07.01.51, Studio 02.07.01.57 headless, logged in):

### Environment prerequisite (was silently broken)

The residual can only be studied with the **genuine** plugin actually loaded. A
stale, wrong plugin (`58a95cf7`) had been left installed; Studio rejects it
("Failed to download the plug-in"), logs the account out, and every "offline"
observation under it is confounded. Installing the genuine `f6f8a47b`
(`~/.cache/bambu_extract_d/plugins/02.07.01.51/`) restores login and a healthy
online baseline (direct cloud: H2S online, temps populate, Lamp enabled).

### Measured timeline (from process launch)

- `~1 s`  — pin branch located (plugin OpenSSL unpacked).
- `~10.7 s` — Studio's FIRST cloud-MQTT connect **and** the one-shot init
  integrity check fire together. Patching the pin before this point kills the
  process at ~first-connect **before any connect reaches the relay**, so there is
  **no clean `[init-clear, first-connect)` window** — the init check *is* gated on
  the first TLS use. The task's primary approach is therefore impossible.
- Cloud retry cadence (pairs, growing backoff): `~10.7, 13.4, 22.4, 37.4, 52.4 s`.
- Periodic re-scan: roughly periodic ~9–14 s; the budget after a late patch varies
  with phase (measured deaths at +5, +9.2, +13.9 s).

### The integrity check kills via `exit(0)` — and it is interceptable

`death_trace` never saw the init-check death because it is **not** a signal or
`std::terminate`: the checker calls plain libc `exit(0)` from
`libbambu_networking.so+0x250f50` (worker-thread entry `+0x5584f5`) — the SAME
function the periodic `std::terminate` (`+0x2f2980`) routes through. A new
`exit_trace.c` LD_PRELOAD shim interposes `exit/_exit/_Exit/quick_exit/abort`
(plus `kill/tgkill/raise`), logs plugin-frame callers, and can neutralize the
plugin's exit:
- `EXIT_BLOCK_PLUGIN=2` **parks** the calling thread — process survives with the
  pin held down **indefinitely**, and crucially with **no** secondary SIGSEGV
  (unlike `tamper_park`'s terminate interception, control E).
- `EXIT_BLOCK_PLUGIN=1` **returns** to the caller — the checker continues but
  falls into the second-stage `std::thread`-dtor `std::terminate` and dies.

### Breakthrough: the account/server UI can be brought ONLINE

Holding the pin down indefinitely (`exit_trace` park, applied **post-boot** so the
init check passed on pristine code and Studio booted) and then forcing Studio's
own server reconnect (click the "Failed to connect to the server" banner) makes the
account/cloud connection **succeed**: the banner clears, and the device selector
lists all printers with **green online dots**. This is strictly past the prior
residual, which could never clear the server latch. It required the *indefinite*
pin-down that only the exit-park enables (the restore method's ~7 s window is too
short to clear the latch).

### Remaining wall: the per-device leg needs the parked thread

With the account online, selecting the H2S drives a device connect ("Connecting…")
but it never completes — no `device/<serial>` subscribe/reports appear, temps stay
`N/A`, Lamp stays disabled. Diagnosis:
- The only cloud socket is the relay (`:9883`); there is no separate external
  tunnel — the device leg rides the same cloud MQTT.
- The worker thread the exit-park **parks** is the one that drives the device
  subscribe/handshake, so parking it (the only way to survive with the pin down
  indefinitely) stalls the device leg. Letting it run instead (`=1` return) hits
  the second-stage `std::terminate` and dies. The anti-tamper is multi-layered on
  a networking-critical thread, so there is no stable config that is both
  pin-down-indefinite **and** device-networking-functional via LD_PRELOAD alone.

The clean fix is to patch the checker itself (`+0x250f50`) so it never signals
tamper — leaving the thread fully functional — rather than intercepting its exit;
that is static RE of the hash routine, the "sturdier alternative" noted above.

### Transport bug fixed along the way

`mitm_redirect.c` rewrote `api.bambulab.com` to a loopback sentinel
*unconditionally*, but only redirects `:443` when `REDIRECT_443` is set. With only
`REDIRECT_MQTT8883` in use (the residual setup) Studio's cloud REST therefore
dialed a dead `127.0.0.2:443` and failed with a cert/host error — breaking the
device-connect handshake in every prior attempt. The rewrite is now gated on
`REDIRECT_443`, so api.bambulab.com resolves directly when no `:443` proxy is
configured. After this fix the device leg progresses to a persistent
"Connecting…" (vs. an immediate "Failed") — necessary but not sufficient given the
thread wall above.

### Net status

- ONLINE achieved for the **account/server** connection (green device dots) under
  the MITM — new.
- The **per-device** connection (and thus the Lamp / `ledctrl`) remains blocked by
  the checker-thread entanglement; the `ledctrl` GUI round-trip could not be
  captured. No `ledctrl` or any device command was ever emitted (Lamp stayed
  disabled throughout); the H2S was never sent a command.
