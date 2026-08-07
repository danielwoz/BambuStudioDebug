# cloud_tap - LD_PRELOAD in-process HTTPS-plaintext capture

Captures the **genuine** closed-source Bambu network plugin's cloud HTTPS request/response plaintext from the plugin's own process heap, for cases the REST MITM (`mitm_redirect.so`) cannot see.

## Why

The genuine plugin **statically links OpenSSL and pins the cloud CA**, so the `mitm_redirect.so` proxy (which needs the pinned verify overridden) never completes TLS and never sees a request/response. But the decrypted HTTP request (request line + X-BBL-* headers + Bearer token) and decrypted response (JSON, PEM cert/key/crl) live briefly in the plugin's PRIVATE heap while a request is in flight. `cloud_tap.so` reads that plaintext straight out of the plugin's own buffers instead of the (encrypted) socket.

Passive (reads /proc/self/maps + /proc/self/mem; no ptrace, no code patches), so it does not trip the plugin's tamper detection. Complements mitm_redirect.so.

## Build
  ./build_cloudtap.sh    # -> cloud_tap.so

## Use
  CLOUD_TAP_OUT=/tmp/cloud_tap.log LD_PRELOAD=$PWD/cloud_tap.so <program> [args...]

Env: CLOUD_TAP_OUT (default /tmp/cloud_tap.log) output file; CLOUD_TAP_WIN (default 8192) window bytes per block.

A constructor spawns the scanner thread at load, so it runs inside the same process as the dlopen'd genuine libbambu_networking.so, reading anonymous readable heap regions for HTTP-plaintext markers (get_app_cert, cert_id, "crl", BEGIN CERTIFICATE, ...).
