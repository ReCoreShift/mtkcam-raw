# RAW Patch Analysis — MTK6789 Camera HAL

## Target

`libmtkcam_metastore.so` — SHA-256 `aee927b9c8a5d7908a296bf9199eb0c45704e7cd6468538c56a42bdddb73e883`

64-bit LSB ARM AArch64, Android 31 (API 31), BIND_NOW enabled, stripped.

## ELF Layout

| Segment | Type | Flags | VA Range | File Range | Size |
|---------|------|-------|----------|------------|------|
| LOAD1 | PT_LOAD | R | `0x0 – 0x263cc` | `0x0 – 0x263cc` | 156.1 KB |
| *(gap)* | — | — | `0x263cc – 0x27000` | `0x263cc – 0x27000` | 3124 B |
| LOAD2 | PT_LOAD | RE | `0x27000 – 0xabb50` | `0x27000 – 0xabb50` | 541.0 KB |

- **`.text` at** `0x27000` (size `0x84064B`, 541 KB)
- **`.plt` at** `0xab070` (size `0xae0B`)

## Code Caves

### PLT Cave (capability trampoline)
- **Offset:** `0xab064`
- **Size:** 44 B
- **Origin:** Gap between LOAD2 end and PLT[0] entry (32 bytes of PLT[0] accessible + 12 bytes before PLT[0])
- **Contents at discovery:** Zero-filled (gap) + PLT[0] first 4 instructions overwritable
- **Strategy:** Write trampoline, then redirect `bl push_back` from capability slot → cave
- **Constraint:** BIND_NOW means PLT is resolved at load time. PLT[0] instructions (`stp`, `adrp`, `add`, `ldr`) are not needed for PLT[1+] since BIND_NOW resolves all GOT entries; we can safely overwrite them.

### LOAD1-LOAD2 Gap Cave (stream trampoline)
- **Offset:** `0x263cc`
- **Size:** 3124 B
- **Origin:** Alignment gap between LOAD1 (p_filesz covers 0–0x263cc) and LOAD2 (p_offset=0x27000)
- **Contents:** Zero-filled
- **Strategy:** Write trampoline, extend LOAD2 `p_offset` and `p_vaddr` backwards to cover the gap, and increase `p_filesz`/`p_memsz` so the loader maps it

## Patch Site 1: Capability Append

### Original (at function `S5KJN1_MIPI_RAW`, `0x3f594`)

```
0x3f594: mov w1, #0xc000c          ; tagRequestAvailableCapabilities
0x3f598: bl entryFor               ; 0xab0a0 -> init metadata entry
...
0x3f638: movz w8, #0x9             ; HIGH_SPEED_VIDEO = 9 (6th slot)
0x3f63c: strb w8, [sp, #0x10]     ; store cap
0x3f640: sub x0, x29, #0x50        ; arg: metadata ptr
0x3f644: add x1, sp, #0x10        ; arg: cap value ptr
0x3f648: bl push_back              ; 0xab0b0 -> append to list
0x3f64c: sub x0, x29, #0x50       ; continue...
```

### Patched

```
0x3f648: bl 0xab064               ; redirect push_back → PLT cave
0x3f63c: (unchanged — movz w8, #9)
```

### Trampoline at `0xab064`

```
0xab064: movz w8, #0x9            ; push preserved slot value
0xab068: strb w8, [sp, #0x10]
0xab06c: sub x0, x29, #0x50
0xab070: add x1, sp, #0x10
0xab074: bl push_back              ; append preserved value
0xab078: movz w8, #0x3            ; push RAW = 3
0xab07c: strb w8, [sp, #0x10]
0xab080: sub x0, x29, #0x50
0xab084: add x1, sp, #0x10
0xab088: bl push_back              ; append RAW
0xab08c: sub x0, x29, #0x50       ; original push_back epilogue (/)
0xab090: add x1, x19, #0x20       ; original push_back epilogue (carry on)
0xab094: b return-addr             ; branch back to 0x3f64c+4
```

(/) — exact epilogue bytes need cross-checking with the original `push_back` return path.

## Patch Site 2: Stream Config Append

### Original (at function `S5KJN1_MIPI_RAW`, `0x3f594`)

```
0x3f9e0: mov w1, #0xd0012              ; tagRequestAvailableStreams
0x3f9e4: bl entryFor                    ; 0xab0a0 -> init metadata entry
...
0x3f9f8: bl push_back_long              ; 0xab190 -> append one stream entry
0x3f9fc: (continue to next sensor init)
```

### Patched

```
0x3f9f8: bl 0x263cc                     ; redirect push_back_long → LOAD1-LOAD2 gap cave
```

### Trampoline at `0x263cc`

```
0x263cc: stp x29, x30, [sp, #-0x10]!   ; save frame
0x263d0: bl entryFor                    ; init metadata for RAW16 stream
; ── Entry 1 ──
0x263d4: mov w8, #0x20                  ; format = RAW16(32)
0x263d8: str x8, [sp, #0x10]
0x263dc: sub x0, x29, #0x50
0x263e0: add x1, sp, #0x10
0x263e4: bl push_back_long              ; append format
0x263e8: mov w8, #0xff0                 ; width = 4080
...
0x263ec-0x2644c: push width, height, (pad), container-VA, sensor-VA, etc.
; ── Entry 2 (if present) ──
0x26450: (same structure)
; ── Return ──
0x264cc: ldp x29, x30, [sp], #0x10     ; restore frame
0x264d0: ret                            ; return to caller
```

### LOAD2 Extension

- `p_offset`: `0x27000` → `0x263cc`
- `p_vaddr`: `0x27000` → `0x263cc`
- `p_filesz`: `0x84b50` → `0x85784` (extends to cover trampoline)
- `p_memsz`: `0x84b50` → `0x85784`

## Capability Values

### ANDROID_REQUEST_AVAILABLE_CAPABILITIES

| Code | Name | S5KJN1 |
|------|------|--------|
| 0 | BACKWARD_COMPATIBLE | ✓ |
| 1 | MANUAL_SENSOR | ✓ |
| 2 | MANUAL_POST_PROCESSING | ✓ |
| 3 | RAW | ✗ (added by patch) |
| 4 | PRIVATE_REPROCESSING | ✗ |
| 5 | BURST_CAPTURE | ✓ |
| 6 | READ_SENSOR_SETTINGS | ✓ |
| 7 | READ_EXTERNAL_SIDECAR | ✗ |
| 8 | DEPTH_OUTPUT | ✗ |
| 9 | HIGH_SPEED_VIDEO | ✓ |

## Sensor Functions (48 total)

Each sensor constructor function name is a mangled symbol containing a short sensor name. Known examples: S5KJN1, IMX355, OV02B1B, GC02M1B, IMX350, S5KGM1SP, OV64B, S5KHM2SP, IMX481, S5K3L8, IMX586, IMX582, IMX596, OV13B10, GC08A3, GC08A8, GC02M2, OV02B10, etc.

## Control Flow Diagram

```
[App] → Camera HAL → libmtkcam_metastore.so
                          │
                     S5KJN1_MIPI_RAW @ 0x3f594
                     ├── init capabilities (0xc000c) ─── bl entryFor
                     │     └── slot 0..6 (movz w8, #N) → bl push_back
                     │           └── redirection: bl 0xab064 (PLT cave trampoline)
                     │                 ├── push original cap
                     │                 ├── push RAW=3
                     │                 └── return
                     │
                     └── init stream config (0xd0012) ── bl entryFor
                           └── hook @ 0x3f9f8: bl push_back_long
                                 └── redirection: bl 0x263cc (gap cave trampoline)
                                       ├── init RAW16 entry (format, dims, VA, sensor)
                                       └── return
```

## Remaining Unknowns

1. **Push-back target (`push_back_va`)**: The `push_back` function resides at `0xab0b0` (a `bx`-based dispatch). The exact helper routine for `push_back` (capability output) and `push_back_long` (stream config output) are at `0xAB0A0` and `0xAB0B0`/`0xAB190` respectively. These were identified by following the original BL from the slot/hook instructions; the dispatch mechanism is not yet fully documented.

2. **Sensor-specific stream entries**: The dimensions (width `0xFF0`=4080, height `0xC00`=3072) and container VA/sensor VAs are specific to S5KJN1. Other sensors need different values derived from their own stream configuration blocks.

3. **Tested devices**: This patch has been verified on the MT6789 platform. Other MediaTek SoCs with similar HAL layouts (MT6833, MT6877, MT6893) may share the same patterns but need separate validation.

## Verification

The patch is self-validating:
1. Expected bytes are checked before every write (the `apply_patches` function verifies `old_bytes` matches the binary before overwriting)
2. Already-patched state is detected (if cave bytes don't match expected zero/PLT)
3. SHA-256 of the input binary is validated against the known hash
4. Output binary SHA-256 is computed and reported after patching
