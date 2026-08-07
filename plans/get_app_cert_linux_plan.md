GET_APP_CERT PLAN - Linux
========================

## Goal
Observe + capture the GENUINE closed-source Bambu get_app_cert HTTPS fetch on Linux.
Windows succeeded (commit ac097b62b) -> app_leaf.pem + slicer_cert_id.txt. Linux has NEVER observed it. We now capture it via a TLS-logging LD_PRELOAD shim, then decrypt the key blob to app_key.pem.

## The gate - DeviceManager.cpp:2428 publish_json
- is_lan_mode_printer() true  -> local_publish_json  (LAN printer -> no app cert needed)
- else -> cloud_publish_json  -> send_message(dev_id, json, qos, flag)  <-- get_app_cert path

The HTTPS get_app_cert = GET api.bambulab.com/v1/iot-service/api/user/applications/<encAppKey>/cert?aes256=<wrapped>&ver=1

## Setup / how to start everything (via root ssh so they persist)
1. Display :  Xvfb :93 -screen 0 1600x1000x24 &
2. VNC:       x11vnc -display :93 -rfbport 5930 -forever -shared -nopw &
3. Bim + app:
   DISPLAY=:93 LD_PRELOAD=/mnt/cephfs/ssd/BambuBridge/shlib/ssl_log.so build/src/bambu-studio
4. Auto Device tab + H2S select (already in source, committed ba5448a54).
5. With LAN printers iptables-blocked, bind a CLOUD device -> get_app_cert fires -> ssl_log.out captures plaintext.

## Build the shim
   gcc -shared -fPIC -O2 -o /mnt/cephfs/ssd/BambuBridge/shlib/ssl_log.so ssl_log.c -ldl
   (logs SSL_read/SSL_write plaintext to /tmp/ssllog.out)

## Root
ssh root@localhost  (passwordless) - full control, can restore iptables.

## Final
Capture the provisioning GET (200) + the `key` blob, feed to win/appcert_recover.cpp -> app_key.pem.
