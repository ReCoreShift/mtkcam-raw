# mtkcam-raw

MediaTek Camera RAW enablement tool — analyzes and patches
`libmtkcam_metastore.so` to expose RAW capture capabilities and RAW16
stream configurations on MediaTek camera HALs.

## Installation

```bash
pip install mtkcam-raw
```

## Usage

### Inspect a library

```bash
mtkcam-raw inspect libmtkcam_metastore.so
```

### Analyze available patch sites

```bash
mtkcam-raw analyze libmtkcam_metastore.so
```

### Patch with config file

```bash
mtkcam-raw --config patch.toml patch libmtkcam_metastore.so \
  -o libmtkcam_metastore_patched.so
```

See `bin/patch.toml` for an example config.

### Verify a patched library

```bash
mtkcam-raw verify libmtkcam_metastore_patched.so
```

## How it works

1. **Capability append** — finds each sensor's `ANDROID_REQUEST_AVAILABLE_CAPABILITIES`
   init block, appends `RAW`, `MANUAL_POST_PROCESSING`, `PRIVATE_REPROCESSING`,
   `READ_SENSOR_SETTINGS_2`, and/or `HIGH_SPEED_VIDEO` via trampolines in unused
   ELF gaps (PLT cave or LOAD1–LOAD2 gap).

2. **Stream config append** — finds each sensor's
   `ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS` init site and appends
   RAW16 stream entries via trampolines, extending LOAD2 `p_filesz`/`p_memsz`
   as needed.
