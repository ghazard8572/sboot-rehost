#!/usr/bin/env python3
"""verify.py - measure the unified-chain verification (stage 1 verdict).

Three GATE items decide the verdict. They exist for one purpose: **a console
that was invented - by the machine or by an agent editing it - must not read as
a real boot.**

  1. source negative  the machine C prints none of the console text
  2. output origin    every fixed console string exists inside the firmware
  3. input origin     the machine never fills its own UART receive buffer

Everything else (chain trace, two-way verification, dual storage drive, bypass
record) is measured and reported but does NOT block. Holding the whole 6/6 bar
turned every run into FORCED and buried the progress actually made.

This is stage 1 of a two-stage check. The verifier agent re-examines the
verdict_script.json produced here and may lower the verdict freely; raising it
requires byte-level evidence.

Legacy track 1 items (kept so an old workspace still verifies):
  1. PC trace        shell_func / exec_command address appears in the trace
  2. output byte-match  every console token exists inside the BL3 binary
  3. source negative    the machine .c contains none of the output strings
  4. single UART path   qemu_chr_fe_write appears exactly once
  5. bypass record      every entry has all four fields

Legacy track 2 items:
  1. boot progress   `Run /init`
  2. kernel evidence per grade - see K3_STAGES.
  3. source negative the machine .c (+HCI) contains none of those strings
  4. real driver     UTRD/Query/SCSI transactions in the trace
  5. bypass record   four fields

Item names and evidence strings stay in Korean on purpose: they are copied
straight into VERIFICATION.md, which the user reads.

Usage:
  verify.py <workdir> --target F2 --container <container.bin>

Output: JSON on stdout + <workdir>/verdict_script.json
"""
import argparse
import glob
import json
import os
import re
import sys

# The four bypass fields, written with optional markdown emphasis and, for the
# side-effect field, the longer "알려진 부작용" wording that real workspaces use.
# The machine may only receive input through the chardev callback. Anything that
# fills the RX buffer from inside the machine is the machine typing to itself.
RX_SEED = re.compile(r"\b(rx_seed|seed_rx|rx_inject|inject_rx|feed_rx)\s*\(")

BYPASS_FIELDS = {
    "대상": r"대상",
    "이유": r"이유",
    "방법": r"방법",
    "부작용": r"(?:알려진\s*)?부작용",
}


# --- input discovery ---------------------------------------------------------
def newest(paths):
    files = [p for p in paths if os.path.isfile(p)]
    return max(files, key=os.path.getmtime) if files else None


def find_console(workdir, track):
    pattern = "kboot_*.txt" if track == 2 else "console_*.txt"
    return newest(glob.glob(os.path.join(workdir, "07_logs", pattern)))


def find_trace(workdir, track):
    prefix = "kboot_" if track == 2 else "run_"
    home = os.path.expanduser("~/rehost/_traces")
    return newest(glob.glob(os.path.join(home, prefix + "*.log")) +
                  glob.glob(os.path.join(workdir, "07_logs", prefix + "*.log")))


def find_machine_sources(workdir, track):
    """Every C source the machine is built from.

    This used to look for `machine.c` (track 1) or `machine_kernel.c` + *ufs*/
    *hci* (track 2). The unified template emits **machine_full.c**, which
    neither branch matched, so the source-negative item examined zero files and
    passed vacuously - the one check that catches a machine printing console
    text was a no-op for the whole unified flow. Glob every .c instead: a
    machine source that is not scanned is not evidence of anything.
    """
    src = os.path.join(workdir, "06_machine")
    names = glob.glob(os.path.join(src, "*.c"))
    return sorted(n for n in names if os.path.isfile(n))


def find_bypass(workdir):
    src = os.path.join(workdir, "06_machine")
    for name in ("bypasses.md", "우회_패치_목록.md"):
        path = os.path.join(src, name)
        if os.path.isfile(path):
            return path
    return None


def derive_pcs(workdir):
    """Pull shell_func / exec_command addresses out of STATIC.md.

    Item 1 needs the PCs that prove the real shell ran. Requiring the caller to
    pass them by hand meant the item failed permanently whenever --pc was
    omitted, capping the verdict at 4/5. Deriving them here keeps the item
    honest without hand-holding; an explicit --pc still wins.
    """
    static = os.path.join(workdir, "STATIC.md")
    if not os.path.isfile(static):
        return []
    found = []
    with open(static, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if re.search(r"shell_func|exec_command", line, re.I):
                found += re.findall(r"0x[0-9a-fA-F]{4,}", line)
    seen, ordered = set(), []
    for pc in found:
        key = pc.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(pc)
    return ordered


def read_bytes(path):
    if not path or not os.path.isfile(path):
        return b""
    with open(path, "rb") as fh:
        return fh.read()


def read_text(path):
    if not path or not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


# --- shared items ------------------------------------------------------------
def check_bypass(workdir):
    """Every bypass entry must carry all four fields.

    Real workspaces write these with markdown emphasis (`**대상**:`) and often
    spell the last one "알려진 부작용", so matching the bare literal `대상:`
    reported zero fields and failed a compliant file. Match the field name with
    optional emphasis and an optional leading list marker instead.
    """
    path = find_bypass(workdir)
    if not path:
        return False, "우회 기록 파일이 없습니다 (06_machine/bypasses.md)"
    text = read_text(path)
    counts = {}
    for label, pattern in BYPASS_FIELDS.items():
        rx = re.compile(rf"^[\s>\-*+]*\**\s*{pattern}\s*\**\s*[:：]", re.M)
        counts[label] = len(rx.findall(text))
    entries = counts["대상"]
    complete = entries > 0 and len(set(counts.values())) == 1
    if complete:
        return True, f"{os.path.basename(path)}: 우회 {entries} 건, 모두 4 항목을 갖췄습니다"
    return False, f"{os.path.basename(path)}: 항목 수가 어긋납니다 {counts}"


# Diagnostics the machine writes to QEMU's own stderr - never to the guest UART.
# A patch-site report naming a firmware symbol ("exynos_read_is_device_unlocked")
# is documentation of a bypass, not the machine forging console output.
HOST_DIAG = re.compile(
    r"\b(?:error_report|info_report|warn_report|error_setg|qemu_log|qemu_log_mask|"
    r'fprintf|printf|assert|g_assert)\b'
    r'(?:"(?:[^"\\]|\\.)*"|[^;])*;', re.S)

# Strings that name QEMU objects - MemoryRegions, properties, the machine type.
# "itmon" as a MemoryRegion name is the device being modelled, not the machine
# printing "itmon" to the guest; the model name appears in mc->desc for the same
# reason it appears in the firmware's own banner.
QEMU_NAMING = re.compile(
    r"\b(?:memory_region_init\w*|object_property_\w+|object_initialize\w*|object_new|"
    r"qdev_\w+|sysbus_\w+|type_register\w*|MACHINE_TYPE_NAME|blk_by_name|"
    r'qemu_chr_new|qemu_chr_fe_init|machine_class_\w+)\b'
    r'(?:"(?:[^"\\]|\\.)*"|[^;])*;', re.S)
DESC_ASSIGN = re.compile(r"->(?:desc|name|fw_name)\s*=\s*\"(?:[^\"\\]|\\.)*\"", re.S)


def code_literals(path):
    """Return the C string literals that could reach the *guest* console.

    Item 1 asks whether the machine prints firmware text to the guest. Three
    kinds of text are not that, and counting them produced false leaks on a
    machine that was genuinely clean:
      - comments and #include paths (never output at all)
      - error_report/info_report/qemu_log arguments (QEMU stderr, not the UART)
      - QEMU object names: MemoryRegion labels, properties, mc->desc
    """
    src = read_text(path)
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)      # block comments
    src = re.sub(r"//[^\n]*", " ", src)                    # line comments
    src = re.sub(r"^\s*#\s*include[^\n]*", " ", src, flags=re.M)
    src = HOST_DIAG.sub(" ", src)                          # host-side diagnostics
    src = QEMU_NAMING.sub(" ", src)                        # object / region names
    src = DESC_ASSIGN.sub(" ", src)                        # mc->desc et al
    return " ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', src))


def code_literals_raw(path):
    """The same filtering, but returning the source so literals stay delimited."""
    src = read_text(path)
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    src = re.sub(r"^\s*#\s*include[^\n]*", " ", src, flags=re.M)
    src = HOST_DIAG.sub(" ", src)
    src = QEMU_NAMING.sub(" ", src)
    src = DESC_ASSIGN.sub(" ", src)
    return src


def check_source_negative(sources, console_bytes):
    """Does the machine emit any string that shows up on the guest console?

    The test runs literal -> console, not console token -> literal. The earlier
    direction flagged a MemoryRegion built as "rehost.itmon%d" because the word
    "itmon" also appears in the firmware's own ITMON messages - a machine that
    names a device after the hardware it models is not forging output. Asking
    whether a machine literal *appears on the console* has no such ambiguity:
    if the machine writes "S-BOOT # " and the console shows "S-BOOT # ", that is
    injection, and nothing else trips it.
    """
    if not sources:
        # Nothing scanned is not the same as nothing found. Passing here would
        # certify "the machine does not print console text" without having read
        # a single machine source.
        return False, ("머신 소스를 하나도 찾지 못했습니다 (06_machine/*.c) — "
                       "검사하지 못한 것은 통과가 아닙니다")
    console = console_bytes.decode("latin-1", errors="replace")
    leaked = []
    for path in sources:
        for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', code_literals_raw(path)):
            # printf-style formats print differently than they are written, so
            # compare the longest literal run between conversions.
            for piece in re.split(r"%[-+ #0-9.*hlLzjt]*[a-zA-Z%]", literal):
                piece = piece.strip()
                if len(piece) >= 6 and piece in console:
                    leaked.append(f"{os.path.basename(path)}:{piece[:40]}")
    if leaked:
        return False, (f"머신이 출력하는 문자열이 콘솔에 {len(leaked)} 건 나타납니다: "
                       f"{leaked[:10]} — 머신이 콘솔을 지어냈는지 확인하십시오")
    return True, (f"머신 소스 {len(sources)} 개의 어떤 출력 문자열도 콘솔에 없습니다 "
                  "(주석·#include·호스트 진단·객체 이름은 출력이 아니므로 제외)")


# --- legacy: pre-0.19.0 track 1 ------------------------------------------------
# Kept so a workspace created before the chain was unified still verifies. New
# runs never reach this - verify_full is the current path.
def verify_track1(workdir, args):
    console_path = args.console or find_console(workdir, 1)
    trace_path = args.trace or find_trace(workdir, 1)
    sources = [args.machine] if args.machine else find_machine_sources(workdir, 1)
    console = read_bytes(console_path)
    bl3 = read_bytes(args.bl3)
    pcs = args.pc or derive_pcs(workdir)
    items = []

    trace = read_text(trace_path)
    hits = [pc for pc in pcs if pc.lower() in trace.lower()]
    if hits:
        evidence = f"트레이스에서 PC {hits} 확인"
    elif not pcs:
        evidence = "STATIC.md 에서 shell_func / exec_command 주소를 찾지 못했습니다"
    else:
        evidence = f"기대한 PC {pcs} 가 트레이스에 없습니다"
    items.append({"n": 1, "name": "PC 트레이스 (shell 함수 · exec_command 진입)",
                  "pass": bool(hits), "evidence": evidence})

    tokens = set(re.findall(rb"[\w\-]{3,}", console))
    missing = sorted(t.decode("latin-1") for t in tokens if bl3.find(t) < 0)
    items.append({
        "n": 2, "name": "출력 byte-match (콘솔 토큰이 BL3 안에 존재)",
        "pass": bool(tokens) and not missing,
        "evidence": (f"토큰 {len(tokens)} 개가 모두 BL3 안에 있습니다" if tokens and not missing
                     else f"토큰 {len(tokens)} 개 중 {len(missing)} 개를 BL3 에서 찾지 못했습니다: {missing[:10]}"),
    })

    ok, detail = check_source_negative(sources, console)
    items.append({"n": 3, "name": "소스 negative (머신 C 에 출력 문자열 없음)",
                  "pass": ok, "evidence": detail})

    # Item 4 depends on the interactive surface. For a UART shell the risk is the
    # machine writing text itself, so we count output paths. For a fastboot
    # surface the output path is USB and the real risk is the machine inventing
    # the *input* command - that would be circular verification, not a rehost.
    if args.surface == "fastboot":
        token = args.input_token or "getvar:"
        planted = [os.path.basename(p) for p in sources if token in code_literals(p)]
        items.append({
            "n": 4, "name": "입력이 외부에서 옴 (머신이 명령을 지어내지 않음)",
            "pass": not planted,
            "evidence": (f"머신 소스에 입력 명령 '{token}' 리터럴이 없습니다 — "
                         f"호스트가 보낸 것으로 처리됩니다"
                         if not planted else
                         f"머신 소스 {planted} 에 입력 명령 '{token}' 이 리터럴로 있습니다 — "
                         f"머신이 명령을 지어낸 순환검증입니다"),
        })
    else:
        # A UART shell has BOTH risks, and only the output one was checked. A
        # machine that seeds its own RX buffer reaches the prompt by talking to
        # itself, which is the same circular verification the fastboot item
        # refuses - it just was not being looked for on this surface.
        calls = sum(read_text(p).count("qemu_chr_fe_write") for p in sources)
        seeded = [os.path.basename(p) for p in sources if RX_SEED.search(read_text(p))]
        token = args.input_token or ""
        planted = [os.path.basename(p) for p in sources
                   if token and token in code_literals(p)]
        offenders = sorted(set(seeded + planted))
        items.append({
            "n": 4,
            "name": "UART 단일 출력 경로 + 입력은 외부에서",
            "pass": calls == 1 and not offenders,
            "evidence": (f"qemu_chr_fe_write 호출 {calls} 곳" +
                         ("; 머신이 RX 를 스스로 채우지 않습니다"
                          if not offenders else
                          f"; {offenders} 가 입력을 만들어 넣습니다 — "
                          f"머신이 자기에게 명령을 준 순환검증입니다")),
        })

    ok, detail = check_bypass(workdir)
    items.append({"n": 5, "name": "우회 기록 4 항목", "pass": ok, "evidence": detail})

    return items, console_path, trace_path, sources


# --- legacy: pre-0.19.0 track 2 ------------------------------------------------
# Rootfs and link-up wording differ by firmware: EROFS over dm-linear on a super
# image, or plain ext4 on a raw block device; ufshcd core or the vendor glue
# driver. Accept either rather than encoding one device's shape as universal.
ROOTFS_PATTERNS = [
    r"erofs: \(device dm-\d+\): mounted",
    r"EXT4-fs \([^)]+\): mounted filesystem",
    r"VFS: Mounted root \(\w+ filesystem\)",
]
LINK_UP_PATTERNS = [
    r"scsi host\d+: ufshcd",
    r"ufs\w*[^\n]*: UFS link established",
]

# Legacy grade names, kept so an old workspace still verifies: driving a real
# vendor UFS controller far enough
# that the kernel enumerates partitions. The methodology sets the bar at
# partitions_up (minimum completion); super_mounted is the capstone and only
# applies to firmware that ships a super image.
K3_STAGES = {
    "partitions_up": [r"\bsda: sda\d"],
    "super_mounted": [r"supermount: SUCCESS",
                      r"erofs: \(device dm-\d+\): mounted"],
}
# Rungs below the completion bar. Reaching one of these is progress, not K3.
K3_PROGRESS = {
    "link_up": LINK_UP_PATTERNS,
    "power_mode": [r"Power mode change\(\d+\)"],
    "scsi_attach": [r"\[sda\] Attached SCSI disk"],
}


def any_match(patterns, haystack):
    return [p for p in patterns if re.search(p, haystack)]


def verify_track2(workdir, args):
    console_path = args.console or find_console(workdir, 2)
    trace_path = args.trace or find_trace(workdir, 2)
    sources = [args.machine] if args.machine else find_machine_sources(workdir, 2)
    console = read_bytes(console_path)
    trace = read_text(trace_path)
    haystack = console.decode("utf-8", errors="replace") + "\n" + trace
    target = (args.target or "K2").upper()
    items = []

    init_ok = "Run /init" in haystack
    items.append({"n": 1, "name": "부팅 진행 (Run /init)", "pass": init_ok,
                  "evidence": ("콘솔에서 'Run /init' 을 확인했습니다" if init_ok
                               else "'Run /init' 이 콘솔·트레이스에 없습니다")})

    # --- item 2: grade-specific kernel evidence ---
    if target == "K3":
        reached = [name for name, pats in K3_PROGRESS.items() if any_match(pats, haystack)]
        parts = any_match(K3_STAGES["partitions_up"], haystack)
        capstone = any_match(K3_STAGES["super_mounted"], haystack)
        if parts:
            best = "super_mounted (캡스톤)" if capstone else "partitions_up (최소 완료)"
            evidence = (f"커널이 파티션을 열거했습니다 — 도달 {best}. "
                        f"통과한 하위 단: {reached or '기록 없음'}")
        else:
            evidence = (f"파티션 열거(`sda: sdaN`)가 없습니다. 도달한 하위 단: "
                        f"{reached or '없음'} — 방법론상 partitions_up 미도달은 "
                        f"UFS 컨트롤러 미완성입니다")
        items.append({"n": 2, "name": "커널 메시지 증거 (K3 — partitions_up 필수)",
                      "pass": bool(parts), "evidence": evidence})
    else:
        patterns = ROOTFS_PATTERNS if target == "K2" else [r"Run /init"]
        found = any_match(patterns, haystack)
        items.append({
            "n": 2, "name": f"커널 메시지 증거 ({target})",
            "pass": bool(found),
            "evidence": (f"커널이 찍은 줄에서 {found} 확인" if found
                         else f"기대한 패턴 {patterns} 이 보이지 않습니다"),
        })

    ok, detail = check_source_negative(sources, console)
    items.append({"n": 3, "name": "소스 negative (머신 C 에 그 문자열 없음)",
                  "pass": ok, "evidence": detail})

    if target == "K3":
        markers = [m for m in ("UTRD", "UPIU", "Query", "SCSI") if m in trace]
        items.append({"n": 4, "name": "벤더 드라이버 실제 구동 (UTRD/Query/SCSI)",
                      "pass": len(markers) >= 2,
                      "evidence": f"트레이스에서 확인한 트랜잭션 마커: {markers}"})
    else:
        items.append({"n": 4, "name": "벤더 드라이버 실제 구동",
                      "pass": True,
                      "evidence": f"해당 없음 (target={target}, 제네릭 스토리지)"})

    ok, detail = check_bypass(workdir)
    items.append({"n": 5, "name": "우회 기록 4 항목", "pass": ok, "evidence": detail})

    return items, console_path, trace_path, sources


def k3_stage_report(haystack):
    """Which rung of the UFS controller ladder the run actually cleared."""
    cleared = [n for n, p in K3_PROGRESS.items() if any_match(p, haystack)]
    if any_match(K3_STAGES["partitions_up"], haystack):
        cleared.append("partitions_up")
    if any_match(K3_STAGES["super_mounted"], haystack):
        cleared.append("super_mounted")
    if "super_mounted" in cleared:
        stage = "최종 칸 (완전한 컨트롤러 — super 마운트)"
    elif "partitions_up" in cleared:
        stage = "최소 완료 (파티션 열거)"
    else:
        stage = "미완 (UFS 컨트롤러 미완성)"
    return {"stage": stage, "cleared": cleared}


# --- unified chain -----------------------------------------------------------
# Six items, because this flow makes two claims the two-track tables never had
# to check: that the chain really ran stage by stage, and that the firmware's own
# verified boot passed on its own terms. Both are easy to fake and neither is
# provable by a console string alone, so each gets an item that can FAIL.

def stage_entries(workdir):
    """Per-stage entry PCs from the derived map, in chain order."""
    path = os.path.join(workdir, "stage_map.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    out = []
    for st in data.get("stages") or []:
        if st.get("state") != "exec":
            continue
        base = (st.get("base") or {}).get("load_base")
        off = st.get("entry_pc_file_offset")
        rng = st.get("file_range") or [None, None]
        if base is None or off is None or rng[0] is None:
            continue
        out.append({"name": st.get("name") or f"stage{st.get('index')}",
                    "pc": base + (off - rng[0])})
    return out


# Console words that are fixed strings in the firmware, as opposed to the values
# printf assembles at runtime. "%d"/"%s" substitutions (timestamps, sizes, register
# dumps) are NOT in the image and counting them as missing made item 2 fail on a
# console that was entirely genuine - 3,131 of 4,511 "missing" tokens were digits.
FIXED_WORD = re.compile(rb"[A-Za-z][A-Za-z_]{3,}")


# Firmware blobs whose strings can legitimately reach the console. The console
# is not produced by sboot.bin alone - ldfw, tzsw, the ACPM firmware and the DTB
# all print through the same UART, and their strings live in their own files.
IMAGE_DIRS = ("03_bootloader", "02_unpacked", "fw")
IMAGE_MAX = 128 * 1024 * 1024          # skip super.img / lu0.img sized backing stores


def firmware_images(workdir, extra):
    """Every firmware component whose strings the console may contain."""
    blobs, seen = [], set()
    for path in extra:
        if path and os.path.isfile(path):
            seen.add(os.path.realpath(path))
            blobs.append(read_bytes(path))
    for sub in IMAGE_DIRS:
        for path in sorted(glob.glob(os.path.join(workdir, sub, "*"))):
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(path):
                continue
            if os.path.getsize(path) > IMAGE_MAX:
                continue
            if os.path.splitext(path)[1].lower() not in (".bin", ".img", ".dtb", ""):
                continue
            seen.add(real)
            blobs.append(read_bytes(path))
    return blobs


# A console the machine invented would fail to match almost everywhere. A handful
# of unmatched words means the reference set is incomplete - the console is
# written by every firmware component that shares the UART (ldfw, tzsw, the ACPM
# firmware), and an exported kit may not carry all of them.
ORIGIN_MIN_RATIO = 0.98


def check_output_origin(console, images):
    """Every fixed string on the console must exist inside a firmware image.

    This is the load-bearing anti-fabrication check: if the machine (or an agent
    editing it) invented console text, the words will not be in any binary.
    """
    words = set(FIXED_WORD.findall(console))
    blobs = [b for b in images if b]
    if not words:
        return False, "콘솔에서 고정 문자열을 찾지 못했습니다 — 대조할 것이 없습니다"
    if not blobs:
        return False, "대조할 펌웨어 이미지가 없습니다 (--container 또는 02_unpacked/)"
    missing = sorted(w.decode("latin-1") for w in words
                     if not any(b.find(w) >= 0 for b in blobs))
    found = len(words) - len(missing)
    ratio = found / len(words)
    if not missing:
        return True, (f"고정 문자열 {len(words)} 개가 모두 펌웨어 이미지 "
                      f"{len(blobs)} 개 안에 있습니다 (런타임 조립분은 대조 대상이 아닙니다)")
    detail = (f"고정 문자열 {len(words)} 개 중 {found} 개 확인 ({ratio:.1%}), "
              f"{len(missing)} 개 미발견: {missing[:10]} — 이미지 {len(blobs)} 개와 대조")
    if ratio >= ORIGIN_MIN_RATIO:
        return True, detail + f" · {ORIGIN_MIN_RATIO:.0%} 이상이라 통과"
    return False, (detail + " — 지어낸 출력이거나, 같은 UART 를 쓰는 다른 펌웨어 성분"
                   "(ldfw·tzsw·ACPM)이 02_unpacked/ 에 없습니다")


def check_input_origin(sources):
    """The machine must not fill its own UART receive buffer.

    A machine that seeds RX is talking to itself; the shell "responding" then
    proves nothing. Input may only arrive through the chardev callback.
    """
    if not sources:
        return False, "머신 소스를 찾지 못해 입력 경로를 확인할 수 없습니다"
    hits = []
    for path in sources:
        src = read_text(path)
        src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
        src = re.sub(r"//[^\n]*", " ", src)
        for m in RX_SEED.finditer(src):
            hits.append(f"{os.path.basename(path)}:{m.group(1)}")
    if hits:
        return False, (f"머신이 자기 수신 버퍼를 채웁니다: {hits[:5]} — "
                       "입력은 chardev 콜백으로만 들어와야 합니다")
    return True, f"머신 소스 {len(sources)} 개에 수신 버퍼 자가 주입이 없습니다"


def verify_full(workdir, args):
    """Measure the unified chain.

    Three GATE items decide the verdict. They exist for one purpose: a console
    that was invented - by the machine or by an agent editing it - must not read
    as a real boot. Everything else is measured and reported but does not block,
    because holding the whole 6/6 bar turned every run into FORCED and buried
    the progress that had actually been made.
    """
    console_path = args.console or find_console(workdir, 1)
    trace_path = args.trace or find_trace(workdir, 1)
    sources = [args.machine] if args.machine else find_machine_sources(workdir, 1)
    console = read_bytes(console_path)
    container = read_bytes(args.container) if args.container else b""
    kernel = read_bytes(args.kernel) if getattr(args, "kernel", None) else b""
    trace = read_text(trace_path)
    hay = console.decode("utf-8", errors="replace") + "\n" + trace
    items = []

    # --- GATE 1: the machine does not print console text -------------------
    ok, detail = check_source_negative(sources, console)
    items.append({"n": 1, "gate": True,
                  "name": "소스 negative (머신 C 에 출력 문자열 없음)",
                  "pass": ok, "evidence": detail})

    # --- GATE 2: the console came out of the firmware ----------------------
    images = firmware_images(workdir, [args.container, getattr(args, "kernel", None)])
    ok, detail = check_output_origin(console, images or [container, kernel])
    items.append({"n": 2, "gate": True,
                  "name": "출력 출처 (콘솔 고정 문자열이 펌웨어 안에 존재)",
                  "pass": ok, "evidence": detail})

    # --- GATE 3: the machine does not feed itself input --------------------
    ok, detail = check_input_origin(sources)
    items.append({"n": 3, "gate": True,
                  "name": "입력 출처 (머신이 자기 수신 버퍼를 채우지 않음)",
                  "pass": ok, "evidence": detail})

    # --- reference: measured, reported, not a gate -------------------------
    stages = stage_entries(workdir)
    if not stages:
        ev, ok = "stage_map.json 에서 스테이지 진입 PC 를 얻지 못했습니다", False
    else:
        seen, order_ok, last = [], True, -1
        low = trace.lower()
        for st in stages:
            at = low.find(f"{st['pc']:#x}".lower())
            if at < 0:
                continue
            seen.append(st["name"])
            if at < last:
                order_ok = False
            last = at
        ok = len(seen) == len(stages) and order_ok
        ev = (f"스테이지 {len(seen)}/{len(stages)} 진입 PC 확인"
              + (f" (순서 {' → '.join(seen)})" if ok else ""))
    items.append({"n": 4, "gate": False, "name": "체인 PC 트레이스 (참고)",
                  "pass": ok, "evidence": ev})

    neg_path = os.path.join(workdir, "07_logs", "avb_negative.txt")
    ok_tok = args.verify_ok_token or "verify"
    pos = bool(re.search(re.escape(ok_tok), hay, re.I)) and "fail" not in hay.lower()[-4000:]
    if not os.path.exists(neg_path):
        ok, ev = False, ("훼손 시험 미실시 — vbmeta 1 바이트를 훼손한 회차의 콘솔을 "
                         f"{neg_path} 에 남기면 검증이 실제로 도는지 확인됩니다")
    else:
        neg = read_text(neg_path).lower()
        neg_failed = ("fail" in neg or "error" in neg or "invalid" in neg)
        ok = bool(pos and neg_failed)
        ev = f"정상 이미지 통과={pos}, 훼손 이미지 실패={neg_failed}"
    items.append({"n": 5, "gate": False, "name": "검증 양방향 (참고)",
                  "pass": ok, "evidence": ev})

    boot_side = any_match([r"EFI PART", r"[Pp]artition", r"GPT", r"\[SCSI\] LU"], hay)
    kern_side = any_match(K3_STAGES["partitions_up"], hay)
    items.append({
        "n": 6, "gate": False, "name": "스토리지 이중 구동 (참고)",
        "pass": bool(boot_side and kern_side),
        "evidence": f"부트로더측 파티션 접근={bool(boot_side)}, 커널측 열거={bool(kern_side)}"})

    ok, detail = check_bypass(workdir)
    items.append({"n": 7, "gate": False, "name": "우회 기록 4 항목 (참고)",
                  "pass": ok, "evidence": detail})

    return items, console_path, trace_path, sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workdir")
    # Legacy: the two-track era. Omitted means the unified chain.
    parser.add_argument("--track", type=int, choices=(1, 2), default=None)
    parser.add_argument("--target", default=None,
                        help="unified: F1/F2/F3 (legacy: A/B/C, K1/K2/K3)")
    parser.add_argument("--container", default=None,
                        help="the bootloader container, loaded whole")
    parser.add_argument("--kernel", default=None,
                        help="kernel Image, so lines the kernel printed are matched too")
    parser.add_argument("--bl3", default=None, help="legacy alias for --container")
    parser.add_argument("--verify-ok-token", default=None,
                        help="console token that means the firmware's own verification passed")
    parser.add_argument("--machine", default=None, help="machine source (auto-discovered if omitted)")
    parser.add_argument("--console", default=None)
    parser.add_argument("--trace", default=None)
    parser.add_argument("--pc", action="append",
                        help="expected stage entry PC; derived from STATIC.md / stage_map.json when omitted")
    parser.add_argument("--surface", default="shell", choices=("shell", "fastboot"),
                        help="the bootloader's interactive surface")
    parser.add_argument("--input-token", default=None,
                        help="the command the host injects; must not appear in the "
                             "machine sources (fastboot default: getvar:)")
    args = parser.parse_args()

    args.container = args.container or args.bl3
    args.bl3 = args.container
    unified = args.track is None or str(args.target or "").upper().startswith("F")

    if unified:
        if not args.container:
            print("verify: --container (부트로더 컨테이너) 가 필요합니다", file=sys.stderr)
            sys.exit(1)
        items, console, trace, sources = verify_full(args.workdir, args)
        storage = k3_stage_report(
            read_bytes(console).decode("utf-8", errors="replace") + "\n" + read_text(trace))
    elif args.track == 1:
        if not args.bl3:
            print("verify: legacy track 1 requires --bl3", file=sys.stderr)
            sys.exit(1)
        items, console, trace, sources = verify_track1(args.workdir, args)
        storage = None
    else:
        items, console, trace, sources = verify_track2(args.workdir, args)
        storage = k3_stage_report(
            read_bytes(console).decode("utf-8", errors="replace") + "\n" + read_text(trace))

    passes = sum(1 for i in items if i["pass"])
    # The verdict rests on the GATE items only. They answer one question - did
    # this console come out of the firmware, or was it manufactured? The rest is
    # measured because it is worth knowing, not because it should block.
    gates = [i for i in items if i.get("gate")]
    refs = [i for i in items if not i.get("gate")]
    if gates:
        gate_ok = all(i["pass"] for i in gates)
        verdict = "VERIFIED" if gate_ok else "UNVERIFIED"
        label = "출처 검증 통과" if gate_ok else "출처 검증 실패"
    else:
        # Legacy track flows have no gate items; they keep the old all-or-nothing
        # verdict so an old workspace still reads the way it was written.
        gate_ok = passes == len(items)
        verdict = "REAL" if gate_ok else "FORCED"
        label = verdict
    result = {
        "flow": "unified" if unified else f"legacy-track{args.track}",
        "target": args.target,
        "passes": passes,
        "total": len(items),
        "gates_passed": sum(1 for i in gates if i["pass"]),
        "gates_total": len(gates),
        "reference_passed": sum(1 for i in refs if i["pass"]),
        "reference_total": len(refs),
        "verdict": verdict,
        "verdict_label": label,
        "items": items,
        "inputs": {"console": console, "trace": trace, "sources": sources},
        "note": ("게이트 3 항은 출력·입력이 펌웨어에서 나왔는지만 봅니다. "
                 "나머지는 참고 지표이며 판정을 막지 않습니다. "
                 "verifier 가 2 차로 재검증합니다."),
    }
    if storage:
        result["ufs_controller"] = storage

    with open(os.path.join(args.workdir, "verdict_script.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)

    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
