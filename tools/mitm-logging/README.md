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
- `mqtt_relay.py` — TLS-terminating MQTT relay for `:8883`. (MQTT)
- `ftps_relay.py` — implicit-FTPS relay for `:990` (control + PASV data). (FTPS)
- `ctrl_relay.py` — native CTRL tunnel relay for `:6000`. (CTRL)
- `capture.sh` — HTTPS orchestrator (shim + mitmdump + slicer).
- `import_flow.py` — folds any capture log into an anonymized `flow.json`.

## Protocol -> flow

| Protocol | Capture | `import_flow.py --flow` |
|----------|---------|--------------------------|
| HTTPS `:443` | `capture.sh` | `login` (or generic `--match`) |
| SSDP `:2021` | `ssdp_sniff.py` | `ssdp_discovery` |
| MQTT `:8883` | `mqtt_relay.py` | `device_command` |
| FTPS `:990` | `ftps_relay.py` | `storage_list` |
| CTRL `:6000` | `ctrl_relay.py` (+ ftps) | `ctrl_storage_list` |

## Example (SSDP — fully passive, no credentials)

```
python3 ssdp_sniff.py --seconds 20 --out ssdp.jsonl
python3 import_flow.py ssdp.jsonl --flow ssdp_discovery --model a1 -o /tmp/ssdp.json
<obn>/build/wire_compliance_test /tmp/ssdp.json
```

LAN relays (MQTT/FTPS/CTRL) need only the printer's access code; see
`../../docs/MITM_LOGGING.md` §4 for the point-and-import recipe per protocol.

## Security

Raw captures under `mitm-captures/`, the mitmproxy CA key (`~/.mitmproxy/`), and
the relay cert/key (`relay_*.pem`) hold live credentials / personal identifiers —
gitignored, **never committed**. Only anonymized fixtures from `import_flow.py`
are committed. Relays redact the FTP/CTRL access code and MQTT never logs it.
