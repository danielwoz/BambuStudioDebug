# MITM wire-logging tooling

Captures the **genuine** closed-source Bambu network plugin's on-wire REST
traffic and turns it into `obn-wire-flow/v1` fixtures for the
open-bamboo-networking (OBN) wire-compliance harness. Full design:
[`../../docs/MITM_LOGGING.md`](../../docs/MITM_LOGGING.md).

## Layout

- `mitm_redirect.c` / `build_redirect.sh` — LD_PRELOAD transport shim. Steers
  `api.bambulab.com:443` through mitmdump, and (when `REDIRECT_8883/990/6000`
  are set) the LAN transports to the relays below. Every other host (login
  webview included) stays direct. Disables cert verification on the redirected
  legs so the interception cert is accepted.
- `wire_addon.py` — mitmdump addon; one NDJSON line per REST request. (HTTPS)
- `ssdp_sniff.py` — passive UDP `:2021` sniffer for printer NOTIFY. (SSDP)
- `mqtt_relay.py` — TLS-terminating MQTT relay for `:8883` (LAN broker). (MQTT)
- `mqtt_cloud_relay.py` — TLS-terminating relay for the region **cloud** broker
  (`*.mqtt.bambulab.com:8883`); logs commands + reports both ways, introspects
  the CONNECT auth (uid/token, redacted), forwards the raw session. (cloud MQTT)
- `ftps_relay.py` — implicit-FTPS relay for `:990` (control + PASV data). (FTPS)
- `ctrl_relay.py` — native CTRL tunnel relay for `:6000`. (CTRL)
- `capture.sh` — HTTPS orchestrator (shim + mitmdump + slicer).
- `import_flow.py` — folds any capture log into an anonymized `flow.json`.

## Protocol -> flow

| Protocol | Capture | `import_flow.py --flow` |
|----------|---------|--------------------------|
| HTTPS `:443` | `capture.sh` | `login`, `filament_manager`, `preset_sync`, `preset_write`, `cloud_print` (or generic `--match`) |
| SSDP `:2021` | `ssdp_sniff.py` | `ssdp_discovery` |
| MQTT `:8883` (LAN) | `mqtt_relay.py` | `device_command` |
| cloud MQTT `:8883` | `mqtt_cloud_relay.py` | `device_command` (cloud ledctrl / print / cloud `project_file`) |
| FTPS `:990` | `ftps_relay.py` | `storage_list` |
| CTRL `:6000` | `ctrl_relay.py` (+ ftps) | `ctrl_storage_list` |
| composite | http + ftps + mqtt (multi-log / session dir) | `hybrid_print`, `lan_print` |

## Example (SSDP — fully passive, no credentials)

```
python3 ssdp_sniff.py --seconds 20 --out ssdp.jsonl
python3 import_flow.py ssdp.jsonl --flow ssdp_discovery --model a1 -o /tmp/ssdp.json
<obn>/build/wire_compliance_test /tmp/ssdp.json
```

LAN relays (MQTT/FTPS/CTRL) need only the printer's access code; see
`../../docs/MITM_LOGGING.md` §4 for the point-and-import recipe per protocol.

## Cloud MQTT (`mqtt_cloud_relay.py`)

The cloud broker leg is long-lived. Point the shim's cloud rule at the relay and
give the relay the region broker host (from the login/profile response):

```
python3 mqtt_cloud_relay.py --broker us.mqtt.bambulab.com --listen-port 9883 \
    --out /tmp/bbl_capture/mqtt_cloud.jsonl \
    --cert /tmp/mitmca/leaf_cert.pem --key /tmp/mitmca/leaf_key.pem
LD_PRELOAD=./mitm_redirect.so REDIRECT_443=9443 REDIRECT_MQTT8883=9883 \
    MITM_CA_DIR=/tmp/certdir <studio>   # add mtls with --upstream-cert/--key if enforced
```

The CONNECT auth is **username/password** (numeric cloud uid + access token),
forwarded raw to the broker; the relay logs only the auth *shape* (token
redacted). `MITM_CA_DIR` is a user-owned CA directory (system roots + the relay
CA) that the shim substitutes for `/etc/ssl/certs/` reads.

**Trust caveat.** The genuine plugin's MQTT TLS uses a statically-linked OpenSSL
whose CA trust is loaded outside libc file calls, so neither `SSL_set_verify`
nor the `MITM_CA_DIR` path-substitution reaches it — the relay cert is rejected
(`unknown ca`) unless the relay CA is added to the real system store
(`/etc/ssl/certs`, root). The transport redirect, relay TLS-terminate + parse +
bidirectional forward, upstream-broker TLS, and the importer path are all
verified independently; the plugin-side trust install is the one root step.

## Security

Raw captures under `mitm-captures/`, the mitmproxy CA key (`~/.mitmproxy/`), the
relay cert/key (`relay_*.pem`), and any cloud MITM CA / mTLS material (keep in a
gitignored `/tmp` dir) hold live credentials / personal identifiers — **never
committed**. Only anonymized fixtures from `import_flow.py` are committed. Relays
redact the FTP/CTRL access code; MQTT never logs the LAN code; the cloud relay
never writes the uid/token.
