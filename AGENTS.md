# mtkcam-raw — agent context

## Project
Patches `libmtkcam_metastore.so` to enable RAW capability and RAW16 stream
config entries on MediaTek camera HALs.

## Architecture
```
src/mtkcam_raw/
  devices.py       Device definitions — frozen dataclasses with validation
  cli.py           CLI — device-agnostic patching engine
  config.py        TOML config merger (overrides device defaults)
  trampoline.py    Trampoline construction (DO NOT MODIFY)
  patch.py         Patch application + verification
  analysis.py      Capability/stream block discovery
  aarch64.py       AArch64 instruction encoding helpers
  cave.py          Code cave discovery and allocation
  elf.py           ELF64 parsing
  metadata.py      Android Camera2 constants
  verify.py        Binary comparison and validation
```

## Key rule
All device-specific offsets, signatures, quirks, and feature flags live in
`devices.py`. Adding a new device requires editing ONLY `devices.py` — no
changes to the generic patching engine in `cli.py`.

## Core types (devices.py)

### `DeviceConfig` (frozen dataclass)
| Field | Purpose |
|---|---|
| `name`, `soc` | Device identity |
| `identity: DeviceIdentity` | Binary fingerprint (SHA256, size, supported versions) |
| `sensor_prefix` | .dynsym prefix for sensor constructors |
| `sensors: tuple[SensorConfig, ...]` | Declarative sensor list |
| `hal_format_meta` | Format → (hal_pixel_format, override_format) |
| `patches: PatchSet` | Structural patch definitions (hwlevel etc.) |
| `plt_cave_va` | PLT-end VA for already-patched detection |
| `desired_cap_tier` | Ordered cap tier list |
| `default_stream_entries` | Fallback RAW16 stream entries |
| `skip_suffixes` | Sub-mode sensor suffixes to skip |
| `quirks: frozenset[DeviceQuirk]` | Typed feature flags |

### `SensorConfig` (frozen dataclass)
| Field | Purpose |
|---|---|
| `prefix` | Name substring match (e.g. `"IMX686"`) |
| `role` | `"back"`, `"front"`, `"depth"`, etc. |
| `priority` | Lower = patched first (< 999 = "main") |
| `raw_enabled` | Whether to add RAW + RAW16 |
| `stream_entries` | Per-sensor override or None |

### `ByteSignature`
- `pattern`, `mask`, `offset_from_match`, `description`
- `resolve(data)` returns file offset or None
- Single-match enforcement by default; raises `SignatureAmbiguous` on multiple
- `allow_multiple=True` accepts first match silently

### `DeviceQuirk` (enum)
- `FORCE_LEVEL_3`, `SKIP_FRONT_RAW`, `NO_RAW16`

### `ValidationIssue`
- `severity` (ERROR/WARNING/INFO), `code`, `message`, `offset`
- Returned by `DeviceConfig.validate_library(data)`

### `PatchSet`
- `hwlevel: Optional[PatchDef]` — csel ne→al in updateHardwareLevel
- `patch_version: str` — track layout changes

### `DeviceIdentity`
- `build_fingerprint`, `library_sha256`, `library_size`, `supported_versions`

## Immutability pattern
`SensorConfig` and `DeviceConfig` are frozen. Use
`device.with_main_sensors(overrides)` to get a modified copy with adjusted
priorities — never mutate in place.

## Signature resolution + caching
`DeviceConfig.resolve_offset(data, sig, cache=None)` scans the binary for a
`ByteSignature`. Pass a `dict` for `cache` to avoid rescanning the same
signature — the cache is keyed by `id(sig)`.

`resolve_patch_offset(data, patch, cache)` tries signature first, falls back
to `patch.fallback_offset`.

## Trampoline approaches
### Old: separate trampoline (`make_capability_append_patches`)
Each sensor gets its own full trampoline body. Safe because each is standalone.

### New: shared trampoline (`make_shared_cap_patches`)
One shared trampoline body + per-sensor stubs (`adr x20, cap_data; b body`).
Saves space when many sensors need the same capabilities.

## Crash root cause (FIXED 2026-07-15)
x20 (callee-saved) was saved to `[sp, #0x80]` around `bl push_back` calls
but push_back wrote to that address, corrupting the reloaded x20.

**Fix:** removed all str/ldr pairs for x20. Callee-saved regs (x19-x28) are
preserved by callee per AAPCS64 — no need to save/restore around calls.
Stack spills only needed for caller-saved regs (x0-x17).

## Testing
```bash
# Single entry point
./build.sh INOI_A75
./build.sh ADVAN_X1
./build.sh --list

# Or invoke directly
python3 -m mtkcam_raw --config bin/patch.inoi_a75.toml --device INOI_A75 \
  patch bin/libmtkcam_metastore.so -o /tmp/patched_inoi.so

python3 -m mtkcam_raw --config bin/patch.advan_x1.toml --device ADVAN_X1 \
  patch ADVAN_X1_libmtkcam_metastore.so -o /tmp/patched_advan.so
```

The test script (`bash bin/test_live.sh`) pushes + bind-mounts + restarts
HAL. It expects `bin/libmtkcam_metastore.patched.so` to exist.

## Validation
Both `validate` and `patch --validate` run `DeviceConfig.validate_library()`
which checks:
- binary size / SHA256
- ELF structure validity
- hwlevel patch site (signature resolution + old_bytes match)
- code cave availability (PLT, LOAD1-LOAD2 gap, LOAD2 end extension)

## Device binaries in repo
- `bin/libmtkcam_metastore.so` — INOI A75 (SHA256 aee927b9c8a5...)
- `ADVAN_X1_libmtkcam_metastore.so` — ADVAN X1 (SHA256 b72c2eea9e84...)

## Compatibility matrix
| Device       | Library version | SHA-256 (first 12)   | Android | Status |
|--------------|----------------|----------------------|---------|--------|
| INOI_A75     | stock          | aee927b9c8a5         | 14      | ✓ validated + patched |
| ADVAN_X1     | stock          | b72c2eea9e84         | 14      | ✓ validated + patched |

## Disassembly workflow
```python
from capstone import *
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
data = open('libmtkcam_metastore.so', 'rb').read()
for i in md.disasm(data[off:off+sz], off): ...
```

## Porting checklist
1. Add `DeviceConfig(...)` to `devices.py`
2. Add `ByteSignature` patterns (or verified `fallback_offset`)
3. `python3 -m mtkcam_raw validate lib.so` — fix issues
4. `python3 -m mtkcam_raw --validate patch lib.so`
5. `python3 -m mtkcam_raw verify orig.so patched.so`
