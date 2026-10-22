# FairPlay enrollment model packs

`fairplay-decrypt --model` is an experimental development override. The only
supported bundled profile is macOS 27.0.1 build 26A428. An external pack
contains a recovered SINF decoder; it does not contain executable code or
require Apple hardware when it is consumed.

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

Generating a new pack is outside the supported ipatool workflow. The CLI can
consume a research-generated pack so recovered models can be tested without
changing Go code, but no compatibility or generation support is promised for
other builds or enrollments.

