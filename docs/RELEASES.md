# BambuStudioDebug MITM tooling — per-version releases (Linux only)

The MITM wire-capture tooling (`tools/mitm-logging/`, see
[`MITM_LOGGING.md`](MITM_LOGGING.md)) is **purely additive** — it touches no
BambuStudio source. It is grafted onto each supported BambuStudio release tag as
a one-commit addition and published as a **prerelease** named `debug-<ver>`,
carrying just the tools (not a BambuStudio build).

> **Linux only.** These releases and the OBN wire-compliance harness the fixtures
> feed are Linux-only today. The capture shim is an `LD_PRELOAD` `.so`, and the
> harness does not support Windows/macOS yet. Windows/macOS capture paths are
> sketched in `MITM_LOGGING.md` §6 but are not part of these releases.

## Supported versions

Grafted from these real release tags (verified present in the repo):

| BambuStudio tag | debug release | branch |
|-----------------|---------------|--------|
| `v02.03.00.70` | `debug-02.03.00.70` | `mitm/02.03.00.70` |
| `v02.03.01.51` | `debug-02.03.01.51` | `mitm/02.03.01.51` |
| `v02.04.00.70` | `debug-02.04.00.70` | `mitm/02.04.00.70` |
| `v02.05.01.58` | `debug-02.05.01.58` | `mitm/02.05.01.58` |
| `v02.05.02.51` | `debug-02.05.02.51` | `mitm/02.05.02.51` |
| `v02.05.03.62` | `debug-02.05.03.62` | `mitm/02.05.03.62` |
| `v02.06.00.51` | `debug-02.06.00.51` | `mitm/02.06.00.51` |
| `v02.06.01.55` | `debug-02.06.01.55` | `mitm/02.06.01.55` |
| `v02.07.00.55` | `debug-02.07.00.55` | `mitm/02.07.00.55` |
| `v02.07.01.62` | `debug-02.07.01.62` | `mitm/02.07.01.62` |
| `v02.08.00.50` | `debug-02.08.00.50` | `mitm/02.08.00.50` |
| `v02.08.01.55` | `debug-02.08.01.55` | `mitm/02.08.01.55` |

All 12 tags exist verbatim in the repository; none required remapping.

## How the releases are cut

`tools/mitm-logging/backport_mitm.sh` grafts the additive fileset onto each tag
and pushes `mitm/<ver>` + `debug-<ver>`. Pushing `debug-<ver>` fires
`.github/workflows/release-mitm.yml` (ubuntu-latest), which builds the redirect
shim, packages the tools + docs, and publishes the prerelease with a
`bambustudiodebug-mitm-tools-<ver>-linux.tar.gz` asset.

```
# dry-run across every supported tag (no push):
tools/mitm-logging/backport_mitm.sh --dry-run

# cut one version:
tools/mitm-logging/backport_mitm.sh --only 02.07.00.55

# cut all:
tools/mitm-logging/backport_mitm.sh
```

The 4-line `CMakeLists.txt` hook that exists on the `mitm-logging` working branch
is intentionally **omitted** from the graft, so applying it is zero-conflict on
every tag. The stock BambuStudio CI workflows are stripped from each `mitm/<ver>`
branch, and the debug release is a **prerelease**, so the default branch's
winget/homebrew `release: released` jobs are not triggered.

## Using a release

1. Download `bambustudiodebug-mitm-tools-<ver>-linux.tar.gz` from the
   `debug-<ver>` prerelease and unpack it.
2. Install prerequisites: `python3`, `pip install mitmproxy`, and your own
   BambuStudio `<ver>` build with the genuine `libbambu_networking.so` plugin.
3. Capture (see `docs/MITM_LOGGING.md` §4 for every protocol):
   ```
   tools/mitm-logging/capture.sh --studio /path/to/bambu-studio     # HTTPS
   python3 tools/mitm-logging/ssdp_sniff.py --seconds 20 --out ssdp.jsonl   # SSDP
   ```
4. Import a flow to an anonymized fixture:
   ```
   python3 tools/mitm-logging/import_flow.py <log> --flow <flow> -o flow.json
   ```

## Slotting fixtures into the OBN harness

The importer emits `obn-wire-flow/v1` fixtures. Drop each under the OBN repo's
version-keyed tree:

```
tests/wire-fixtures/<os>/<network_plugin_version>/<channel>/<printer_model>/<flow>/flow.json
```

- `<os>` is `linux` (only OS supported today).
- `<network_plugin_version>` is the `bambu_network_agent/<ver>` on the wire —
  **the plugin/agent version, which is not always the slicer `<ver>`**. Read it
  from the fixture's `meta.network_plugin_version` (the importer fills it from the
  `User-Agent`), e.g. a slicer `02.07.00.55` capture reports agent `02.07.00.50`.
- `<channel>` ∈ `cloud | cloud_lan | lan`; `<printer_model>` ∈ `account | h2s |
  h2d | a1 | …`; `<flow>` ∈ `login | preset_sync | start_print | …`.

Then run the harness to see where OBN diverges from genuine:

```
cmake -S <obn> -B <obn>/build -DOBN_BUILD_TESTS=ON -DOBN_VERSION=<ver>
cmake --build <obn>/build --target wire_compliance_test
<obn>/build/wire_compliance_test <path>/flow.json    # or: ctest -R wire_
```
