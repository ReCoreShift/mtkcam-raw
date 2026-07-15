# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Configuration file support — TOML-based patch configuration.

Allows users to specify patch settings in a single config.toml
instead of passing many CLI flags.
"""

# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from __future__ import annotations

import tomllib
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mtkcam_raw.metadata import (
    StreamEntry,
    stream_entry_from_dict,
    resolve_format,
    HAL_PIXEL_FORMAT_RAW16,
    FORMAT_NAMES,
)


@dataclass
class PatchConfig:
    """Settings that can be loaded from config.toml."""
    sensor: Optional[str] = None
    all: bool = False
    main_sensors: list[str] = field(default_factory=list)
    caps: list[str] = field(default_factory=list)
    tier: list[str] = field(default_factory=list)
    stream: bool = False
    stream_entries: list[StreamEntry] = field(default_factory=list)
    sensor_streams: dict[str, list[StreamEntry]] = field(default_factory=dict)
    sensor_tiers: dict[str, list[str]] = field(default_factory=dict)
    quiet: bool = False
    output: Optional[str] = None


def load_config(path: Path) -> PatchConfig:
    """
    Read and parse a TOML config file into a PatchConfig.
    """
    data = path.read_bytes()
    parsed = tomllib.loads(data.decode("utf-8"))
    return _parse_toml_to_config(parsed)


def _parse_toml_to_config(parsed: dict) -> PatchConfig:
    cfg = PatchConfig()

    if "sensor" in parsed:
        cfg.sensor = str(parsed["sensor"])
    if "all" in parsed:
        cfg.all = bool(parsed["all"])
    if "main_sensors" in parsed:
        raw = parsed["main_sensors"]
        if isinstance(raw, list):
            cfg.main_sensors = [str(v) for v in raw]
    if "caps" in parsed:
        raw = parsed["caps"]
        if isinstance(raw, list):
            cfg.caps = [str(v) for v in raw]
    if "tier" in parsed:
        raw = parsed["tier"]
        if isinstance(raw, list):
            cfg.tier = [str(v) for v in raw]
    if "stream" in parsed:
        cfg.stream = bool(parsed["stream"])
    if "sensor_streams" in parsed:
        raw = parsed["sensor_streams"]
        if isinstance(raw, dict):
            for sensor_name, entries_raw in raw.items():
                if isinstance(entries_raw, list):
                    entries: list[StreamEntry] = []
                    for entry in entries_raw:
                        if isinstance(entry, dict):
                            entries.append(stream_entry_from_dict(entry))
                        elif isinstance(entry, list):
                            # positional: [format, width, height, direction, hal, override]
                            n = len(entry)
                            fmt = resolve_format(entry[0]) if n > 0 else HAL_PIXEL_FORMAT_RAW16
                            w = int(str(entry[1]), 0) if n > 1 else 0
                            h = int(str(entry[2]), 0) if n > 2 else 0
                            d = int(str(entry[3]), 0) if n > 3 else 0
                            hp = int(str(entry[4]), 0) if n > 4 else None
                            ov = int(str(entry[5]), 0) if n > 5 else None
                            entries.append(StreamEntry(
                                width=w, height=h, format=fmt,
                                direction=d, hal_pixel_format=hp,
                                override_format=ov,
                            ))
                    cfg.sensor_streams[sensor_name] = entries
    if "stream_entries" in parsed:
        raw = parsed["stream_entries"]
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    cfg.stream_entries.append(stream_entry_from_dict(entry))
                elif isinstance(entry, list):
                    # Old-style positional: [format, width, height, direction, hal, override]
                    n = len(entry)
                    fmt = resolve_format(entry[0]) if n > 0 else HAL_PIXEL_FORMAT_RAW16
                    w = int(str(entry[1]), 0) if n > 1 else 0
                    h = int(str(entry[2]), 0) if n > 2 else 0
                    d = int(str(entry[3]), 0) if n > 3 else 0
                    hp = int(str(entry[4]), 0) if n > 4 else None
                    ov = int(str(entry[5]), 0) if n > 5 else None
                    cfg.stream_entries.append(StreamEntry(
                        width=w, height=h, format=fmt,
                        direction=d, hal_pixel_format=hp,
                        override_format=ov,
                    ))
    if "quiet" in parsed:
        cfg.quiet = bool(parsed["quiet"])
    if "output" in parsed:
        cfg.output = str(parsed["output"])

    return cfg


def _entry_to_cli_string(entry: StreamEntry) -> str:
    """Serialize a StreamEntry to the CLI comma-separated format."""
    t = entry.to_tuple()
    parts: list[str] = []
    for i, v in enumerate(t):
        if i >= 4:  # hal_pixel_format, override_format as hex
            parts.append(hex(v))
        else:
            parts.append(str(v))
    return ",".join(parts)


def merge_config_into_args(
    config: PatchConfig,
    args: dict,
    defaults: dict,
) -> dict:
    """
    Override CLI defaults with config file values.

    Only applies when the CLI arg is still at its parser default
    (i.e., the user did not explicitly pass it).
    """
    overrides: dict[str, object] = {}

    # sensor: str | None
    if config.sensor is not None and args.get("sensor") == defaults.get("sensor"):
        overrides["sensor"] = config.sensor

    # main_sensors: list[str] (not a CLI flag, attach to namespace)
    if config.main_sensors:
        overrides["main_sensors"] = config.main_sensors

    # all: bool
    if config.all and not args.get("all"):
        overrides["all"] = True

    # caps: list[str] from config -> comma-separated str for CLI
    if config.caps and args.get("caps") == defaults.get("caps", ""):
        overrides["caps"] = ",".join(config.caps)

    # tier: list[str] from config -> comma-separated str for CLI
    if config.tier and args.get("tier") == defaults.get("tier", ""):
        overrides["tier"] = ",".join(config.tier)

    # stream: bool
    if config.stream and not args.get("stream"):
        overrides["stream"] = True

    # stream_entries: StreamEntry list -> CLI list of comma-sep strings
    if config.stream_entries and not args.get("stream_entries_list"):
        overrides["stream_entries_list"] = [
            _entry_to_cli_string(entry)
            for entry in config.stream_entries
        ]

    # sensor_streams: per-sensor entries dict (not a CLI flag)
    if config.sensor_streams:
        overrides["sensor_streams"] = {
            k: [_entry_to_cli_string(e) for e in v]
            for k, v in config.sensor_streams.items()
        }

    # quiet
    if config.quiet and not args.get("quiet"):
        overrides["quiet"] = True

    # output
    if config.output is not None and args.get("output") == defaults.get("output"):
        overrides["output"] = Path(config.output)

    args.update(overrides)
    return args


def generate_default() -> str:
    """Return the default config.toml content as a string."""
    fmt_names = ", ".join(FORMAT_NAMES.values())
    return textwrap.dedent(f"""\
        # mtkcam-raw configuration
        # Uncomment and adjust values as needed.

        # Sensor name substring filter (optional)
        # sensor = "S5KJN1"

        # Include sub-mode sensor variants
        # all = false

        # Capabilities to append (comma-separated names or integer values)
        # caps = ["RAW", "BURST_CAPTURE"]

        # Tier: desired capability set — only missing ones are appended, in this order
        # Overrides `caps` when both are present.
        # tier = ["RAW", "MANUAL_SENSOR", "MANUAL_POST_PROCESSING", "BURST_CAPTURE", "PRIVATE_REPROCESSING", "HIGH_SPEED_VIDEO"]

        # Append RAW16 stream config entries
        # stream = true

        # Stream configuration entries — either a positional list:
        # [format, width, height, direction, hal_pixel_format, override_format]
        # stream_entries = [
        #     [32, "0xFF0", "0xC00", 0, "0x3F940AA", "0x1FCA055"],
        # ]
        #
        # Or named fields (format and direction default to RAW16 / OUTPUT):
        # [[stream_entries]]
        # width = 4080
        # height = 3072
        # # format = "RAW16"       # {fmt_names}
        # # direction = 0           # 0=OUTPUT, 1=INPUT
        # # hal_pixel_format = "0x3F940AA"
        # # override_format = "0x1FCA055"
        #
        # Per-sensor stream entries (overrides the global stream_entries above):
        # [sensor_streams]
        # S5KJN1 = [
        #     {{width = 4080, height = 3072}},
        #     {{width = 1920, height = 1080, format = "YUV_420_888"}},
        # ]
        # S5K3L6 = [
        #     {{width = 4208, height = 3120}},
        # ]

        # Suppress per-sensor progress messages
        # quiet = false

        # Output file path (default: input path with .patched.so suffix)
        # output = "/tmp/libmtkcam_metastore_patched.so"
    """)
