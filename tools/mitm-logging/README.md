# MITM wire-logging tooling

Captures the **genuine** closed-source Bambu network plugin's on-wire REST
traffic and turns it into `obn-wire-flow/v1` fixtures for the
open-bamboo-networking (OBN) wire-compliance harness. Full design:
[`../../docs/MITM_LOGGING.md`](../../docs/MITM_LOGGING.md).

## Layout

- `mitm_redirect.c` / `build_redirect.sh` — LD_PRELOAD transport shim. Steers
  ONLY `api.bambulab.com` through a local mitmdump; every other host (login
  webview included) stays direct. Disables cert verification on the redirected
  leg so mitmproxy's interception cert is accepted.
- `wire_addon.py` — mitmdump addon that appends each request/response to an
  NDJSON log (method, path, query, ordered headers, body, status).
- `capture.sh` — one command: builds the shim, starts mitmdump reverse-proxy,
  launches BambuStudio with the genuine plugin, logging to a gitignored dir.
- `import_flow.py` — folds a captured log into an anonymized `flow.json`.

## Workflow

```
# 1. capture (needs a built bambu-studio + the genuine plugin installed)
tools/mitm-logging/capture.sh --studio ./build/src/bambu-studio
#    log in, reproduce the problem in the UI, quit. Raw log lands in
#    ./mitm-captures/http_all.jsonl (gitignored).

# 2. import one flow into an anonymized fixture
python3 tools/mitm-logging/import_flow.py mitm-captures/http_all.jsonl \
    --flow login --model account --channel cloud \
    -o /tmp/flow.json

# 3. drop it into the OBN tree and run the harness
cp /tmp/flow.json \
  <obn>/tests/wire-fixtures/linux/02.07.00.50/cloud/account/login/flow.json
ctest --test-dir <obn>/build -R wire_ --output-on-failure
```

`import_flow.py` has a precise recognizer for `login` and a generic best-effort
mode (`--match <path-substring>`) for other flows.

## Security

Raw captures under `mitm-captures/` and the mitmproxy CA key (`~/.mitmproxy/`)
hold live tokens and personal identifiers — gitignored, **never committed**.
Only anonymized fixtures from `import_flow.py` are committed.
