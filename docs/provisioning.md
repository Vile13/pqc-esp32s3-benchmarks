# Provisioning

What has to exist before a device can complete a handshake, and how to create it.

Two files hold deployment state and are **gitignored**:

| File | Contents | Secret? |
|---|---|---|
| `firmware/esp32s3-dut/main/device_config.h` | Wi-Fi credentials, server address, device_id, PSK | **yes** |
| `firmware/esp32s3-dut/main/server_key.h` | pinned server ML-KEM public key | no, but deployment-specific |

## 1. Server key pair

Generated on the Pi, private half never leaves it:

```bash
python3 tools/pin_server_key.py --host volker@192.168.188.53
```

This creates `~/pqc-server/server_dk.pem` on the Pi with mode `0600` if it does
not exist, reads back only the public key, and writes `server_key.h`.

Re-running it is safe: an existing key pair is reused, not replaced. To rotate
deliberately, delete `server_dk.pem` on the Pi first — and note that every client
then has to be reflashed, because pinning is what authenticates the server.

The script prints a `server_key_id` and a SHA-256 fingerprint. Compare the
fingerprint against the Pi if you want independent confirmation:

```bash
ssh volker@192.168.188.53 \
  'openssl pkey -in ~/pqc-server/server_dk.pem -pubout -outform DER | tail -c 1184 | sha256sum'
```

## 2. Device configuration

```bash
cd firmware/esp32s3-dut/main
cp device_config.h.example device_config.h
```

Then fill in the values. Wi-Fi credentials are typed by hand; the two random
values are generated, not invented.

### device_id — 8 bytes, not secret

```bash
openssl rand -hex 8 | sed 's/../0x&, /g'
```

Paste into `DEVICE_ID`. It travels in the clear so the server can find the right
PSK; it only needs to be unique across your devices.

### PSK — 32 bytes, secret

```bash
openssl rand -hex 32 | sed 's/../0x&, /g'
```

Paste into `DEVICE_PSK`.

This is worth doing properly. Per [protocol.md](protocol.md) the PSK is mixed
into the key schedule next to the ML-KEM shared secret, not merely used as an
authentication token. That gives two independent lines of defence — an adversary
who breaks ML-KEM still faces 256 bits of symmetric secret — but only if those
256 bits are actually random. A hand-typed passphrase throws the property away
while leaving the code looking identical.

### Register the PSK with the server

```bash
python3 tools/register_device.py --host volker@192.168.188.53
```

This reads `device_id` and the PSK out of `device_config.h` and writes them into
`~/pqc-server/devices.json` on the Pi, mode `0600`.

The PSK is passed to the Pi on stdin of the ssh invocation. It is not put on a
command line, where it would be visible in `ps` to every other user on the
machine and would land in shell history on both ends, and it is not written to a
temporary file. The tool prints only a truncated SHA-256 of it, which is enough
to confirm both ends hold the same value without exposing it.

Re-running the tool for an existing `device_id` replaces that entry.

## 3. Wi-Fi

`WIFI_SSID` and `WIFI_PASSWORD` in the same file.

One consequence worth knowing: the ESP32's hardware RNG only guarantees true
randomness while the radio is up (see [hardware.md](hardware.md)). The protocol
firmware therefore brings Wi-Fi up *before* generating any nonce or calling the
randomized ML-KEM API. A build without Wi-Fi must not run this protocol, and the
`randombytes()` implementation refuses to serve one.

## 4. Verify

```bash
. ~/esp/esp-idf/export.sh
cd firmware/esp32s3-dut
idf.py build
```

The build fails with a pointed message if either header is missing.

## What is deliberately not automated

Wi-Fi credentials are not read from the environment, fetched over SSH, or
prompted for by a script. They are typed into a gitignored file by the person who
owns them. The same goes for the PSK: the commands above are run by you, and the
values are not printed anywhere they could end up in a log or a transcript.

Flash encryption and Secure Boot are out of scope for v1, which means a device
that is physically opened gives up both its PSK and the pinned server key. That
is stated as a non-goal in [protocol.md](protocol.md) rather than quietly
assumed away.
