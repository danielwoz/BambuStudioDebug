# socklog — LD_PRELOAD socket tracer

Records every BSD socket call a process makes, with peer address and payload
hex. Used to capture the genuine Bambu network plugin's raw UDP/TCP flows —
specifically the TUTK/IOTC camera protocol, which the REST-level MITM
(`mitm_redirect.so`) cannot observe because the plugin self-resolves DNS and
runs the camera transport as raw UDP to the printer, not HTTPS to a known host.

It wraps libc entry points only (no ptrace, no code patching), so it does not
trip the plugin's tamper detection.

## Build

```
./build_socklog.sh            # -> socklog.so
```

Self-contained: `gcc -shared -fPIC -ldl -lpthread`.

## Use

```
SOCKLOG_OUT=/path/session.txt LD_PRELOAD=./socklog.so <program> [args…]
```

| Env           | Default             | Meaning                                    |
|---------------|---------------------|--------------------------------------------|
| `SOCKLOG_OUT` | `/tmp/socklog.txt`  | Output file (opened once, appended).       |
| `SOCKLOG_MAX` | `2048`              | Payload bytes logged as hex (0 = headers). |

Interposed calls: `socket`, `bind`, `connect`, `setsockopt`, `send`, `sendto`,
`sendmsg`, `recvfrom`, `recvmsg`. Writes are serialised with a mutex, so lines
from concurrent threads stay intact.

## Line format

```
<sec>.<usec> T<tid> <call> fd=<fd> [to=|from=<ip:port>] [len=<n>] -> <ret> [data=<hex>]
```

Example (genuine H2S TUTK camera session):

```
… sendto fd=126 to=45.79.40.130:10240 len=54 -> 54 data=ee2f8cec40d1…   # master LOOKUP
… sendto fd=126 to=192.168.1.2:36337 len=88 -> 88 data=6e4c9d8c40d1…  # directed LAN_SEARCH3
… sendto fd=126 to=192.168.1.2:36337 len=285 -> 285 data=6e6c5df2…    # DTLS ClientHello (IOTC-wrapped)
… recvfrom fd=126 from=192.168.1.2:36337 -> 1117 data=4e6f4d12…       # DTLS ApplicationData (video)
```

The TUTK datagrams are scrambled with `trans_code_partial` (key
`"Charlie is the d"`). Decode and parse them with `../tutk_decode.py`, and turn
a whole session into an OBN wire-compliance fixture with `../import_tutk_flow.py`.

## Notes

- A `socklog.txt` from a real session contains live secrets (cloud UID, session
  tokens, authkey, passwd). It is a raw capture — treat it like credentials and
  never commit it. `import_tutk_flow.py` redacts those before writing a fixture.
- `.so` build artifacts here are gitignored.
