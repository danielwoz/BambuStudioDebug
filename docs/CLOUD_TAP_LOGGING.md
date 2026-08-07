# cloud_tap wire-logging (in-process HTTPS-plaintext capture)

Companion to `tools/mitm-logging/` for the case the transport MITM (`mitm_redirect.so`) cannot see the genuine Bambu network plugin's cloud HTTPS traffic.

## Why the REST MITM fails

The genuine `libbambu_networking.so` statically links OpenSSL and pins the cloud CA. A proxy MITM terminates TLS with its own interception cert; the plugin's pinned verify rejects it, the handshake never completes, and no request/response reaches the proxy. This is exactly what blocks capturing `get_app_cert` (and other pinned cloud REST) traffic.

## What cloud_tap does

While a request is in flight, the plugin holds the decrypted HTTP request (request line + X-BBL-* headers + Bearer token) and the decrypted response (JSON, PEM cert/key/crl) in its PRIVATE heap. `cloud_tap.so` runs a background thread (spawned from a shared-object constructor inside the dlopen'd plugin process) that reads anonymous readable heap regions via /proc/self/maps + /proc/self/mem and dumps blocks containing HTTP-plaintext markers (get_app_cert, cert_id, "crl", BEGIN CERTIFICATE, ...) to `$CLOUD_TAP_OUT`. Passive (no ptrace, no patches) - does not trip tamper checks.

## Use
  tools/mitm-logging/cloud_tap/capture_cloudtap.sh [--studio BIN] [--out DIR] [-- <studio args>]
Launches BambuStudio with cloud_tap.so preloaded; reproduces the cloud call; quit. The plaintext request/response blocks (get_app_cert, cert_id, BEGIN CERTIFICATE, ...) land in <out>/cloud_tap.log.
## Security
Raw captures contain live tokens and personal identifiers - gitignored, never committed.
