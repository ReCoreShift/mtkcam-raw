# mtkcam-raw

Analyze and patch `libmtkcam_metastore.so` to expose RAW capture
capabilities and RAW16 stream configurations on MediaTek camera HALs.

## Install

```bash
git clone https://github.com/ReCoreShift/mtkcam-raw.git
cd mtkcam-raw
pip install -e .
```

## Quick start

```bash
# Place the stock library in bin/ (or project root)
cp /path/to/stock/libmtkcam_metastore.so bin/

# Patch it with main sensors + RAW16 stream entries
bash bin/patch.sh
# Output: bin/libmtkcam_metastore.patched.so

# Push to device and test
bash bin/test_live.sh
```

## Subcommands

| Command | Description |
|---------|-------------|
| `inspect` | Show ELF structure, sections, and segment layout |
| `analyze` | Find and describe all patch sites per sensor |
| `patch` | Apply capabilities and/or stream config patches |
| `verify` | Compare original and patched binary byte-for-byte |
| `gen-config` | Generate a default `patch.toml` from a library |

## Patch configuration (`bin/patch.toml`)

```toml
main_sensors = ["S5KJN1", "S5K3L6"]

tier = ["RAW", "MANUAL_POST_PROCESSING", "PRIVATE_REPROCESSING",
        "READ_SENSOR_SETTINGS_2", "HIGH_SPEED_VIDEO"]

stream = true

[sensor_streams]
S5KJN1 = [{width = 4080, height = 3072}]
S5K3L6 = [{width = 4208, height = 3120}]
```

| Field | Description |
|-------|-------------|
| `main_sensors` | Sensor names that get first priority for cave space |
| `tier` | Capabilities to append to each sensor's block |
| `stream` | Whether to append RAW16 stream config entries |
| `sensor_streams` | Per-sensor stream entries (width, height) |

## How it works

1. **Capability append** — finds each sensor's
   `ANDROID_REQUEST_AVAILABLE_CAPABILITIES` init block, appends missing
   capabilities (RAW, MANUAL_POST_PROCESSING, etc.) via trampolines
   written into unused ELF gaps (PLT cave or LOAD1–LOAD2 gap).

2. **Stream config append** — finds each sensor's
   `ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS` init site and appends
   RAW16 stream entries via trampolines, extending LOAD2
   `p_filesz`/`p_memsz` as needed.

3. **Space allocation** — uses a priority-sorted allocator across three
   cave types: PLT[0] gap, LOAD1–LOAD2 gap (extended backward), and
   LOAD2 trailing zero-padding (extended forward).

## License

MPL-2.0
