"""Tests for configuration file support."""


import os
import tempfile
from pathlib import Path
from mtkcam_raw.config import (
    PatchConfig,
    load_config,
    generate_default,
    merge_config_into_args,
)
from mtkcam_raw.metadata import StreamEntry
from mtkcam_raw.devices import INOI_A75


def _write_toml(content: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=".toml", text=True)
    os.write(fd, content.encode("utf-8"))
    os.close(fd)
    return Path(path)


class TestLoadConfig:
    def test_empty_config(self):
        path = _write_toml("")
        cfg = load_config(path)
        assert cfg.sensor is None
        assert cfg.all is False
        assert cfg.caps == []
        assert cfg.stream is False
        assert cfg.stream_entries == []
        assert cfg.quiet is False
        assert cfg.output is None

    def test_all_fields(self):
        path = _write_toml("""\
sensor = "S5KJN1"
all = true
caps = ["RAW", "BURST_CAPTURE"]
tier = ["RAW", "MANUAL_SENSOR"]
stream = true
quiet = true
output = "/tmp/patched.so"

[[stream_entries]]
width = 4080
height = 3072
format = "RAW16"
""")
        cfg = load_config(path)
        assert cfg.sensor == "S5KJN1"
        assert cfg.all is True
        assert cfg.caps == ["RAW", "BURST_CAPTURE"]
        assert cfg.tier == ["RAW", "MANUAL_SENSOR"]
        assert cfg.stream is True
        assert cfg.quiet is True
        assert cfg.output == "/tmp/patched.so"
        assert len(cfg.stream_entries) == 1
        e = cfg.stream_entries[0]
        assert e.width == 4080
        assert e.height == 3072
        assert e.format == 32
        assert e.direction == 0

    def test_old_style_list_entries(self):
        path = _write_toml("""\
stream = true
stream_entries = [
    [32, "0xFF0", "0xC00", 0, "0x3F940AA", "0x1FCA055"],
    [32, 2048, 1536],
]
""")
        cfg = load_config(path)
        assert len(cfg.stream_entries) == 2
        e0 = cfg.stream_entries[0]
        assert e0.width == 0xFF0
        assert e0.height == 0xC00
        assert e0.format == 32
        assert e0.hal_pixel_format == 0x3F940AA
        e1 = cfg.stream_entries[1]
        assert e1.width == 2048
        assert e1.height == 1536
        assert e1.direction == 0
        assert e1.hal_pixel_format is None
        t1 = e1.to_tuple(INOI_A75.hal_format_meta)
        assert t1[4] == 0x3F940AA

    def test_partial_config(self):
        path = _write_toml('caps = ["RAW"]\nsensor = "IMX"')
        cfg = load_config(path)
        assert cfg.sensor == "IMX"
        assert cfg.caps == ["RAW"]
        assert cfg.stream is False

    def test_dict_entry_with_format_name(self):
        path = _write_toml("""\
[[stream_entries]]
width = 1920
height = 1080
format = "YUV_420_888"
direction = "OUTPUT"
""")
        cfg = load_config(path)
        assert len(cfg.stream_entries) == 1
        e = cfg.stream_entries[0]
        assert e.width == 1920
        assert e.height == 1080
        assert e.format == 33
        assert e.direction == 0


class TestMergeConfigIntoArgs:
    def test_merges_defaults(self):
        cfg = PatchConfig(
            sensor="S5KJN1",
            caps=["RAW", "BURST_CAPTURE"],
            tier=["RAW", "MANUAL_SENSOR"],
            stream=True,
            stream_entries=[StreamEntry(width=4080, height=3072)],
            quiet=True,
            output="/tmp/out.so",
        )
        args = {
            "sensor": None,
            "all": False,
            "caps": "",
            "tier": "",
            "stream": False,
            "stream_entries_list": [],
            "quiet": False,
            "output": None,
        }
        defaults = {
            "sensor": None,
            "caps": "",
            "tier": "",
            "stream": False,
            "stream_entries_list": [],
            "quiet": False,
            "output": None,
            "all": False,
        }

        merged = merge_config_into_args(
            cfg, args, defaults, INOI_A75.hal_format_meta,
        )

        assert merged["sensor"] == "S5KJN1"
        assert merged["caps"] == "RAW,BURST_CAPTURE"
        assert merged["tier"] == "RAW,MANUAL_SENSOR"
        assert merged["stream"] is True
        assert merged["quiet"] is True
        assert len(merged["stream_entries_list"]) == 1
        assert merged["output"] == Path("/tmp/out.so")

    def test_cli_flags_take_precedence(self):
        cfg = PatchConfig(caps=["RAW"], tier=["RAW", "MANUAL_SENSOR"], sensor="S5KJN1")
        args = {
            "sensor": "IMX586",
            "caps": "",
            "tier": "",
            "stream": True,
        }
        defaults = {"sensor": None, "caps": "", "tier": "", "stream": False}

        merged = merge_config_into_args(
            cfg, args, defaults, INOI_A75.hal_format_meta,
        )

        assert merged["sensor"] == "IMX586"
        assert merged["caps"] == "RAW"
        assert merged["tier"] == "RAW,MANUAL_SENSOR"
        assert merged["stream"] is True


class TestGenerateDefault:
    def test_output_is_valid_toml(self):
        import tomllib
        content = generate_default()
        parsed = tomllib.loads(content)
        assert isinstance(parsed, dict)

    def test_all_keys_documented(self):
        content = generate_default()
        for key in ["sensor", "all", "caps", "tier", "stream", "stream_entries", "quiet", "output"]:
            assert key in content
