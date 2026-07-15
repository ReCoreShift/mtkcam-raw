# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
CLI — command parsing and output presentation for mtkcam-raw.
"""

# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from mtkcam_raw.elf import parse_elf
from mtkcam_raw.cave import CaveAllocator
from mtkcam_raw.analysis import (
    find_sensor_symbols,
    analyze_all_capabilities,
    find_all_stream_hooks,
    find_capability_block,
    discover_binary_profile,
)
from mtkcam_raw.metadata import (
    cap_name,
    sensor_short_name,
    is_submode,
    CAP_NAME_TO_VALUE,
)
from mtkcam_raw.trampoline import (
    make_capability_append_patches,
    make_stream_append_patches,
    parse_stream_entries,
)
from mtkcam_raw.patch import (
    PatchRecord,
    write_patched_file,
)
from mtkcam_raw.config import (
    load_config,
    generate_default,
    merge_config_into_args,
)
from mtkcam_raw.verify import (
    compare_binaries,
    validate_elf_structure,
    detect_already_patched,
)


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect ELF structure."""
    data = args.path.read_bytes()
    errors = validate_elf_structure(data)
    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        return 1

    image = parse_elf(data)

    print(f"Library: {args.path}")
    print(f"  SHA256:  {image.sha256}")
    print(f"  Size:    {len(data)} bytes")
    print("  ELF:     64-bit LSB ARM AArch64")
    print(f"  BIND_NOW: {'yes' if image.check_bind_now() else 'no'}")
    print()

    print("Program headers:")
    for ph in image.phdrs:
        if ph.is_load:
            print(f"  PT_LOAD [{ph.index}] {ph.flags_str}:")
            print(f"    VA      0x{ph.p_vaddr:08x} - 0x{ph.p_vaddr + ph.p_filesz:08x}")
            print(f"    File    0x{ph.p_offset:08x} - 0x{ph.p_offset + ph.p_filesz:08x}")

    print()
    print("Sections:")
    for name, sec in sorted(image.sections.items()):
        if sec.is_allocated or sec.is_executable:
            flag_s = ""
            if sec.flags & 1:
                flag_s += "W"
            if sec.flags & 2:
                flag_s += "A"
            if sec.flags & 4:
                flag_s += "X"
            print(f"  {name:20s} addr=0x{sec.addr:08x} size=0x{sec.size:06x} [{flag_s}]")

    from mtkcam_raw.cave import find_plt_cave, find_load12_gap
    plt_cave = find_plt_cave(image)
    if plt_cave:
        print(f"\nPLT cave: 0x{plt_cave.va:x} ({plt_cave.size}B)")

    gap_cave = find_load12_gap(image)
    if gap_cave:
        print(f"LOAD1-LOAD2 gap: 0x{gap_cave.va:x} ({gap_cave.size}B)")

    sensors = find_sensor_symbols(image)
    print(f"\nSensor functions: {len(sensors)}")
    for s in sensors[:5]:
        print(f"  0x{s.value:08x}  {sensor_short_name(s.name)}")
    if len(sensors) > 5:
        print(f"  ... and {len(sensors) - 5} more")

    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze binary for patch sites."""
    data = args.path.read_bytes()
    image = parse_elf(data)

    print(f"Analyzing {args.path}")
    print(f"  SHA256: {image.sha256}")
    print()

    # Capability blocks
    cap_blocks = analyze_all_capabilities(image)
    print(f"Capability blocks found: {len(cap_blocks)}")

    for block in cap_blocks:
        if args.sensor and args.sensor.upper() not in block.sensor_name.upper():
            continue
        if not args.all and is_submode(block.sensor_name):
            continue

        cap_str = " ".join(f"{cap_name(v)}({v})" for v in block.values)
        print(f"\n  {block.sensor_name}:")
        print(f"    Function: 0x{block.function_va:08x} (sz=0x{block.function_size:x})")
        print(f"    Tag 0xc000c: file 0x{block.tag_file_offset:x}")
        print(f"    Capabilities: [{cap_str}]")

        for slot in block.slots:
            print(f"      slot 0x{slot.file_offset:06x}: {cap_name(slot.value)}({slot.value})")
            print(f"        -> bl 0x{slot.push_back_target_va:x}")

    # Stream hooks
    stream_hooks = find_all_stream_hooks(image)
    print(f"\nStream config hooks (tag 0xd0012): {len(stream_hooks)}")
    for hook in stream_hooks:
        if args.sensor and args.sensor.upper() not in hook.sensor_name.upper():
            continue
        print(f"  {hook.sensor_name}: bl entryFor at 0x{hook.hook_va:x}")
        print(f"    Tag at file 0x{hook.tag_file_offset:x}")

    # Binary profile
    try:
        profile = discover_binary_profile(image)
        print("\nBinary profile:")
        print(f"  entry_for_va   = 0x{profile.entry_for_va:x}")
        print(f"  push_long_va   = 0x{profile.push_long_va:x}")
    except ValueError:
        pass

    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    """Apply patches to enable RAW support."""
    data = args.path.read_bytes()
    image = parse_elf(data)

    print(f"Patching {args.path}")
    print(f"  Input SHA256: {image.sha256}")

    if not args.output:
        args.output = args.path.with_suffix(".patched.so")

    in_path = args.path
    out_path = args.output

    allocator = CaveAllocator.from_image(image)
    if allocator.remaining == 0:
        print("ERROR: No suitable code cave found")
        return 1

    # Discover binary helper addresses
    try:
        profile = discover_binary_profile(image)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    patches: list[PatchRecord] = []

    # Determine desired cap set: --tier overrides --caps
    cap_spec: str | None = None
    cap_intent: str = ""
    if args.tier:
        cap_spec = args.tier
        cap_intent = "tier"
    elif args.caps:
        cap_spec = args.caps
        cap_intent = "caps"

    main_sensors: list[str] = getattr(args, "main_sensors", [])
    syms = find_sensor_symbols(image)

    def priority_key(sym):
        sname = sensor_short_name(sym.name)
        for i, m in enumerate(main_sensors):
            if m in sname:
                return i
        return 999

    syms.sort(key=priority_key)

    def find_sensor_sym(sensor_syms, sensor_name):
        for s in sensor_syms:
            if sensor_short_name(s.name) == sensor_name:
                return s
        return sensor_syms[0] if sensor_syms else None

    if cap_spec:
        if not image.check_bind_now():
            print("ERROR: BIND_NOW not set; PLT[0] cave is unsafe")
            return 1

        desired_caps = parse_cap_values(cap_spec)
        print(f"\nDesired capabilities ({cap_intent}): {[cap_name(c) for c in desired_caps]}")

        # Phase 1: main sensors' caps
        for sym in syms:
            if priority_key(sym) >= 999:
                continue
            sname = sensor_short_name(sym.name)
            if args.sensor and args.sensor.upper() not in sname.upper():
                continue
            if not args.all and is_submode(sname):
                if not args.quiet:
                    print(f"  {sname}: [SKIP] sub-mode")
                continue

            block = find_capability_block(image, sym.value, sym.size)
            if block is None:
                print(f"  {sname}: [SKIP] no capability block")
                continue

            missing = [c for c in desired_caps if c not in block.values]
            if not missing:
                print(f"  {sname}: all desired caps present")
                continue

            last_slot = block.slots[-1]
            if last_slot.push_back_target_va is None:
                print(f"  {sname}: [SKIP] cannot decode push_back target")
                continue

            push_back_va = last_slot.push_back_target_va

            if not args.quiet:
                missing_str = ", ".join(cap_name(c) for c in missing)
                print(f"  {sname}: appending {missing_str}")
                print(f"    slot 0x{last_slot.file_offset:06x}: {cap_name(last_slot.value)}({last_slot.value}) (preserved)")

            try:
                cap_patches = make_capability_append_patches(
                    image, last_slot.file_offset,
                    missing, push_back_va, allocator,
                )
                patches.extend(cap_patches)
            except ValueError as e:
                print(f"  {sname}: [SKIP] {e}")
                continue


    if args.stream:
        stream_hooks = find_all_stream_hooks(image)
        if not stream_hooks:
            print("ERROR: No stream config hooks found")
            return 1

        print(f"\nStream config: {len(stream_hooks)} camera(s)")

        sensor_streams: dict[str, list[str]] = getattr(args, "sensor_streams", {})

        def stream_priority(h):
            for i, m in enumerate(main_sensors):
                if m in h.sensor_name:
                    return i
            return 999

        stream_hooks.sort(key=stream_priority)

        for hook in stream_hooks:
            if priority_key(find_sensor_sym(syms, hook.sensor_name)) >= 999:
                continue  # non-main sensors after caps spread
            if args.sensor and args.sensor.upper() not in hook.sensor_name.upper():
                continue

            hook_entries = None
            for sens, e_list in sensor_streams.items():
                if sens.upper() in hook.sensor_name.upper():
                    hook_entries = e_list
                    break
            if hook_entries is None:
                hook_entries = args.stream_entries_list

            entries = parse_stream_entries(hook_entries)
            if not entries:
                entries = [(32, 640, 480, 0, 0x3F940AA, 0x1FCA055)]

            try:
                stream_patches = make_stream_append_patches(
                    image, hook.hook_va, profile, allocator, entries,
                )
                patches.extend(stream_patches)
            except ValueError as e:
                print(f"  {hook.sensor_name}: [SKIP] {e}")
                continue
            if not args.quiet:
                print(f"  {hook.sensor_name}: hook 0x{hook.hook_va:x} -> cave ({len(entries)} entries)")


    if cap_spec:
        cap_other_done = 0
        cap_other_skip = 0
        for sym in syms:
            if priority_key(sym) < 999:
                continue
            sname = sensor_short_name(sym.name)
            if args.sensor and args.sensor.upper() not in sname.upper():
                continue
            if not args.all and is_submode(sname):
                continue

            block = find_capability_block(image, sym.value, sym.size)
            if block is None:
                continue

            missing = [c for c in desired_caps if c not in block.values]
            if not missing:
                continue

            last_slot = block.slots[-1]
            if last_slot.push_back_target_va is None:
                continue

            try:
                cap_patches = make_capability_append_patches(
                    image, last_slot.file_offset,
                    missing, last_slot.push_back_target_va, allocator,
                )
                patches.extend(cap_patches)
                if not args.quiet:
                    missing_str = ", ".join(cap_name(c) for c in missing)
                    print(f"  {sname}: appending {missing_str}")
                cap_other_done += 1
            except ValueError:
                cap_other_skip += 1

        if not args.quiet and cap_other_done:
            print(f"\nOther sensor caps: {cap_other_done} patched, {cap_other_skip} skipped (no space)")


    if args.stream:
        stream_other_done = 0
        stream_other_skip = 0
        for hook in stream_hooks:
            if priority_key(find_sensor_sym(syms, hook.sensor_name)) < 999:
                continue
            if args.sensor and args.sensor.upper() not in hook.sensor_name.upper():
                continue

            hook_entries = None
            for sens, e_list in sensor_streams.items():
                if sens.upper() in hook.sensor_name.upper():
                    hook_entries = e_list
                    break
            if hook_entries is None:
                hook_entries = args.stream_entries_list

            entries = parse_stream_entries(hook_entries)
            if not entries:
                entries = [(32, 640, 480, 0, 0x3F940AA, 0x1FCA055)]

            try:
                stream_patches = make_stream_append_patches(
                    image, hook.hook_va, profile, allocator, entries,
                )
                patches.extend(stream_patches)
                if not args.quiet:
                    print(f"  {hook.sensor_name}: hook 0x{hook.hook_va:x} -> cave ({len(entries)} entries)")
                stream_other_done += 1
            except ValueError:
                stream_other_skip += 1

        if not args.quiet and stream_other_done:
            print(f"\nOther sensor streams: {stream_other_done} patched, {stream_other_skip} skipped (no space)")

    if not patches:
        print("\nNothing to patch.")
        return 0

    print(f"\nApplying {len(patches)} patches...")
    result = write_patched_file(in_path, out_path, patches)

    if result.is_valid:
        print(f"  Patched -> {out_path}")
        print(f"  Output SHA256: {result.output_sha256}")
        print(f"  Patch records: {len(result.records)}")
        for r in result.records:
            print(f"    0x{r.file_offset:06x}: {r.description}")
        return 0
    else:
        print(f"  Patching FAILED ({len(result.errors)} errors):")
        for e in result.errors:
            print(f"    {e}")
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify original vs patched binary."""
    original = args.original.read_bytes()
    patched = args.patched.read_bytes()

    result = compare_binaries(original, patched)

    print(f"Original SHA256: {result.original_sha256}")
    print(f"Patched   SHA256: {result.patched_sha256}")

    errors = validate_elf_structure(patched)
    if errors:
        print("\nPatched ELF structure issues:")
        for e in errors:
            print(f"  {e}")

    if result.regions:
        print(f"\nChanged regions: {len(result.regions)}")
        for r in result.regions:
            short_old = r.old_bytes[:16].hex()
            short_new = r.new_bytes[:16].hex()
            if len(r.old_bytes) > 16:
                short_old += "..."
            if len(r.new_bytes) > 16:
                short_new += "..."
            print(f"  0x{r.file_offset:06x}-0x{r.file_offset + r.size:06x} ({r.size}B)")
            print(f"    old: {short_old}")
            print(f"    new: {short_new}")
    else:
        print("\nNo differences found (binaries are identical).")

    # Detect already-patched state
    PLT_CAVE_VA = 0xAB064  # .text end in this binary
    if detect_already_patched(original, patched, PLT_CAVE_VA):
        print("\n[DETECTED] Patched binary shows BL redirects to cave — appears already patched.")

    print(f"\nTotal changed bytes: {result.total_changed}")
    return 0


def cmd_gen_config(args: argparse.Namespace) -> int:
    """Generate a default config.toml."""
    content = generate_default()
    if args.output:
        args.output.write_text(content)
        print(f"Config written to {args.output}")
    else:
        print(content, end="")
    return 0


def parse_cap_values(value_str: str) -> list[int]:
    """Parse comma-separated cap values or names -> list of ints."""
    result = []
    for token in value_str.split(","):
        token = token.strip()
        if not token:
            continue
        if token.isdigit():
            result.append(int(token))
        elif token.upper() in CAP_NAME_TO_VALUE:
            result.append(CAP_NAME_TO_VALUE[token.upper()])
        else:
            print(f"ERROR: Unknown capability '{token}'")
            sys.exit(1)
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mtkcam-raw",
        description="MediaTek Camera RAW enablement analysis and patching tool",
    )
    parser.set_defaults(func=lambda _: parser.print_help() or 1)

    parser.add_argument(
        "--config", type=Path,
        help="Path to config.toml (settings merged with CLI flags)",
    )

    sub = parser.add_subparsers(title="commands")

    # Collect per-subparser defaults for config merging
    _sub_defaults: dict[str, dict[str, object]] = {}

    # inspect
    p_inspect = sub.add_parser(
        "inspect", help="Show ELF structure and metadata"
    )
    p_inspect.add_argument("path", type=Path, help="Path to .so library")
    p_inspect.set_defaults(func=cmd_inspect)
    _sub_defaults["inspect"] = {}

    # analyze
    p_analyze = sub.add_parser(
        "analyze", help="Find and describe patch sites"
    )
    p_analyze.add_argument("path", type=Path, help="Path to .so library")
    p_analyze.add_argument("--sensor", help="Filter by sensor name substring")
    p_analyze.add_argument(
        "--all", action="store_true",
        help="Include sub-mode sensor variants",
    )
    p_analyze.set_defaults(func=cmd_analyze)
    _sub_defaults["analyze"] = {
        a.dest: a.default for a in p_analyze._actions
        if a.default is not argparse.SUPPRESS
    }

    # patch
    p_patch = sub.add_parser(
        "patch", help="Apply patches to enable RAW support"
    )
    p_patch.add_argument("path", type=Path, help="Input .so library")
    p_patch.add_argument("-o", "--output", type=Path, default=None,
                         help="Output path")
    p_patch.add_argument(
        "--caps", type=str, default="",
        help='Capabilities to append (e.g. "RAW" or "RAW,BURST_CAPTURE")',
    )
    p_patch.add_argument(
        "--tier", type=str, default="",
        help='Desired capability set; only missing ones are appended in this order '
             '(e.g. "RAW,MANUAL_SENSOR,MANUAL_POST_PROCESSING"). Overrides --caps.',
    )
    p_patch.add_argument(
        "--sensor", help="Only patch specific sensor name substring",
    )
    p_patch.add_argument(
        "--main_sensors", nargs="*", default=[],
        help=argparse.SUPPRESS,
    )
    p_patch.add_argument(
        "--all", action="store_true",
        help="Include sub-mode sensor variants",
    )
    p_patch.add_argument(
        "--stream", action="store_true",
        help="Append RAW16 stream config entries",
    )
    p_patch.add_argument(
        "--stream-entries", type=str, action="append", default=[],
        dest="stream_entries_list",
        help=(
            'Stream entry fields as comma-separated hex/decimal values '
            '(e.g. "32,0xFF0,0xC00,0,0x3F940AA,0x1FCA055"). '
            'Use multiple --stream-entries for multiple entries.'
        ),
    )
    p_patch.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress per-sensor progress messages",
    )
    p_patch.set_defaults(func=cmd_patch)
    _sub_defaults["patch"] = {
        a.dest: a.default for a in p_patch._actions
        if a.default is not argparse.SUPPRESS
    }

    # verify
    p_verify = sub.add_parser(
        "verify", help="Compare original and patched binaries"
    )
    p_verify.add_argument("original", type=Path, help="Original .so")
    p_verify.add_argument("patched", type=Path, help="Patched .so")
    p_verify.set_defaults(func=cmd_verify)
    _sub_defaults["verify"] = {}

    # gen-config
    p_gen = sub.add_parser(
        "gen-config", help="Generate a default config.toml"
    )
    p_gen.add_argument(
        "-o", "--output", type=Path,
        help="Output path (prints to stdout if omitted)",
    )
    p_gen.set_defaults(func=cmd_gen_config)

    args = parser.parse_args(argv)

    # Merge config.toml into parsed args (CLI flags take precedence)
    if hasattr(args, "config") and args.config:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"ERROR: Failed to load config: {e}", file=sys.stderr)
            return 1

        # Determine which subcommand was invoked
        invoked = getattr(args, "func", None)
        sub_name = None
        for name, cmd_func in [
            ("inspect", cmd_inspect),
            ("analyze", cmd_analyze),
            ("patch", cmd_patch),
            ("verify", cmd_verify),
        ]:
            if invoked is cmd_func:
                sub_name = name
                break

        defaults = _sub_defaults.get(sub_name, {})
        args_dict = vars(args)
        merge_config_into_args(config, args_dict, defaults)
        args = argparse.Namespace(**args_dict)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
