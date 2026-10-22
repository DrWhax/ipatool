# FairPlay enrollment model packs

`fairplay-decrypt --model` accepts a private model produced by a matching
FairPlay provisioning run. The model contains the enrollment-specific SINF
decoder; it does not contain executable code or require Apple hardware when it
is consumed.

All integers are little-endian. Version 1 is exactly 4,176 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| `0x0000` | 8 | `FPSENR1\0` (external pack) or legacy `FPS26A4\0` |
| `0x0008` | 4 | Format version (`1`) |
| `0x000c` | 4 | Complete pack size (`4176`) |
| `0x0010` | 32 | SHA-256 of the `fairplayd` build used for recovery |
| `0x0030` | 16 | Recovered AES-128 key |
| `0x0040` | 16 | External-byte whitening period |
| `0x0050` | 4096 | Sixteen 256-byte inverse input permutations |

Every input table must be a permutation of all byte values. The SINF decoder
also validates the complete clear `key `/`iviv`/`tmpr`/`righ`/`name` atom
layout before accepting a logical key.

The pack contains private enrollment key material. Keep it mode `0600`; the
CLI rejects group- or world-readable model files and refuses to overwrite the
model even when `--force` is set.

Generating a new pack is a separate provisioning operation. On current macOS,
FairPlayIOKit selector `0x15` ultimately uses device-bound hardware AES. The
hardware key never needs to leave the device, but opening the user client
requires Apple's private `com.apple.private.FairPlayIOKitUserClient.access`
entitlement. A normal process, including root, receives `0xe00002c2`.
Therefore a production provisioner must use an authorized Apple-service relay
or import the output of a matching trusted provisioning helper; ipatool must
not embed, emulate, or claim to extract the fused hardware key.

