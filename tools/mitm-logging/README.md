# MITM wire-logging tooling

Records every network interaction BambuStudioDebug performs and turns it into
`obn-wire-flow/v1` fixture skeletons. Full design: [`../../docs/MITM_LOGGING.md`](../../docs/MITM_LOGGING.md).

## Layout

- `recorder/` — dependency-free NDJSON wire recorder (`wire_recorder.{hpp,cpp}`).
  Shared by the OSS `obn` plugin (the real interception layer) and, optionally,
  by the slicer via `-DBBL_MITM_LOGGING=ON`. Builds and self-tests standalone:
  ```
  cmake -S recorder -B recorder/build && cmake --build recorder/build
  ctest --test-dir recorder/build            # wire_recorder_smoke
  ```
- `run_with_logging.sh` — launches a built `bambu-studio` with capture env set
  (`BBL_MITM_CAPTURE_DIR`, `BBL_MITM_FLOW/MODEL/CHANNEL`, `OBN_WIRE_RECORD=1`).
- `export_fixtures.py` — folds a raw session NDJSON into an anonymized
  `flow.skeleton.json` for human review.

## Capture → fixture workflow

```
# 1. build obn with the recorder (Phase 2 wiring) + this fork's bambu-studio
# 2. capture a flow (raw NDJSON lands in the gitignored ./mitm-captures/)
tools/mitm-logging/run_with_logging.sh --flow start_print --model h2s --channel cloud_lan
# ... drive the flow in the UI, then quit ...

# 3. export + anonymize into a review skeleton
python3 tools/mitm-logging/export_fixtures.py \
    mitm-captures/session-<ts>-start_print.ndjson --out /tmp/skeletons

# 4. review vs the hand-authored fixtures, then hand-place under
#    obn-cloud-header-order/tests/wire-fixtures/...
```

## Security

Raw captures under `mitm-captures/` contain live tokens and personal
identifiers — the dir is gitignored and **must never be committed**. Only
anonymized, human-reviewed fixtures are committed. Never commit the slicer
signing key, `BambuNetworkEngine.conf`, or any baked key value.
