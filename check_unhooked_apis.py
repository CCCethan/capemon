#!/usr/bin/env python3
"""
Check which Windows APIs imported by PoC executables are NOT
implemented as hooks in capemon (hooks.h).

Uses PE import tables (via pefile) — only external DLL imports appear,
so custom/inline functions never cause false positives.

Usage:
    python check_unhooked_apis.py <poc_exe_dir> <capemon_dir> [output.json]

Output JSON:
    {
        "unhooked_count": int,
        "unhooked_apis": [{"api": str, "dll": str}, ...],
        "poc_api_count": int,
        "hooked_api_count": int,
        "capemon_hook_total": int,
        "poc_files": int,
        "coverage_rate": float,
        "by_dll": {"DLL.dll": ["Api1", ...], ...}
    }
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    sys.exit("ERROR: pefile not installed. Run: pip install pefile --break-system-packages")

# Functions automatically injected by MSVC CRT startup/runtime — NOT written
# by the developer. Excluding these avoids false negatives in coverage analysis.
# Criteria: functions that MSVC CRT always imports regardless of source code.
CRT_NOISE: set[str] = {
    # FLS (Fiber-Local Storage) — CRT internal thread management
    "FlsAlloc", "FlsFree", "FlsGetValue", "FlsSetValue",
    # TLS (Thread-Local Storage) — CRT internal
    "TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue",
    # C++ SEH / exception unwinding — compiler-generated, never explicit
    "RtlCaptureContext", "RtlLookupFunctionEntry", "RtlPcToFileHeader",
    "RtlUnwind", "RtlUnwindEx", "RtlVirtualUnwind",
    "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
    # CRT security cookies
    "EncodePointer", "DecodePointer",
    # CRT heap (operator new/delete implementation)
    "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize", "GetProcessHeap",
    # CRT synchronization primitives (std::mutex etc.)
    "InitializeCriticalSectionAndSpinCount", "InitializeCriticalSectionEx",
    "DeleteCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
    "InitializeSListHead",
    # CRT locale / codepage (std::string, printf internals)
    "GetCPInfo", "GetACP", "GetOEMCP",
    "IsValidCodePage", "IsValidLocale",
    "LCMapStringW", "LCMapStringEx",
    "GetStringTypeW", "CompareStringW",
    "EnumSystemLocalesW", "GetUserDefaultLCID",
    "GetLocaleInfoW", "GetDateFormatW", "GetTimeFormatW",
    # CRT startup sequence
    "GetStartupInfoW", "GetCommandLineA", "GetCommandLineW",
    "GetModuleHandleExW", "GetModuleFileNameW",
    "ExitProcess", "TerminateProcess",
    # CRT stdio / console init
    "GetFileType", "GetConsoleMode", "GetConsoleOutputCP",
    "ReadConsoleW", "WriteConsoleW",
    "FlushFileBuffers", "GetStdHandle", "SetStdHandle",
    # CRT environment
    "GetEnvironmentStringsW", "FreeEnvironmentStringsW",
    # CRT wide/multi-byte conversion (std::string ↔ wstring)
    "MultiByteToWideChar", "WideCharToMultiByte",
    # CRT timing baseline (std::chrono internals)
    "GetSystemTimeAsFileTime",
    # CRT error reporting
    "SetLastError", "RaiseException",
}

# Windows system DLLs to consider as "Windows API" sources.
# Set to None to include ALL imported DLLs (including third-party).
WINDOWS_DLLS: set[str] | None = {
    "kernel32.dll", "kernelbase.dll",
    "ntdll.dll",
    "user32.dll", "gdi32.dll", "win32u.dll",
    "advapi32.dll",
    "ole32.dll", "oleaut32.dll", "combase.dll",
    "shell32.dll", "shlwapi.dll",
    "ws2_32.dll", "winhttp.dll", "wininet.dll",
    "secur32.dll", "crypt32.dll", "ncrypt.dll",
    "wtsapi32.dll", "winspool.drv",
    "dbghelp.dll", "psapi.dll",
    "netapi32.dll", "netbios.dll",
    "setupapi.dll", "cfgmgr32.dll",
    "pdh.dll", "powrprof.dll",
    "iphlpapi.dll",
    "mpr.dll",
    "version.dll",
    "msi.dll",
    "wevtapi.dll",
    "mf.dll", "mfplat.dll",
    "d3d11.dll",
}


def extract_hooked_apis(capemon_dir: Path) -> set[str]:
    hooks_h = capemon_dir / "hooks.h"
    if not hooks_h.exists():
        sys.exit(f"ERROR: {hooks_h} not found")
    import re
    pattern = re.compile(r"HOOKDEF\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)")
    return {m.group(1) for m in pattern.finditer(
        hooks_h.read_text(encoding="utf-8", errors="ignore")
    )}


def extract_imported_apis(poc_dir: Path) -> tuple[dict[str, set[str]], int]:
    """
    Returns:
        api_to_dlls: {api_name -> set of DLL names that export it}
        file_count
    """
    api_to_dlls: dict[str, set[str]] = {}
    file_count = 0

    for exe_file in sorted(poc_dir.rglob("*.exe")):
        try:
            pe = pefile.PE(str(exe_file), fast_load=False)
        except pefile.PEFormatError as e:
            print(f"  WARN: cannot parse {exe_file.name}: {e}", file=sys.stderr)
            continue

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            continue

        file_count += 1
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="replace").lower()
            if WINDOWS_DLLS is not None and dll_name not in WINDOWS_DLLS:
                continue
            for imp in entry.imports:
                if not imp.name:
                    continue  # skip ordinal-only imports
                api = imp.name.decode(errors="replace")
                if api in CRT_NOISE:
                    continue  # skip CRT-injected imports
                api_to_dlls.setdefault(api, set()).add(dll_name)

        pe.close()

    return api_to_dlls, file_count


def main():
    parser = argparse.ArgumentParser(
        description="Find Windows APIs in PoC executables not hooked by capemon"
    )
    parser.add_argument("poc_dir", help="Directory containing PoC .exe files")
    parser.add_argument("capemon_dir", help="capemon source directory (must contain hooks.h)")
    parser.add_argument(
        "output",
        nargs="?",
        default="unhooked_apis.json",
        help="Output JSON file (default: unhooked_apis.json)",
    )
    args = parser.parse_args()

    poc_dir = Path(args.poc_dir)
    capemon_dir = Path(args.capemon_dir)

    if not poc_dir.is_dir():
        sys.exit(f"ERROR: PoC exe directory not found: {poc_dir}")
    if not capemon_dir.is_dir():
        sys.exit(f"ERROR: capemon directory not found: {capemon_dir}")

    print("Extracting hooked APIs from hooks.h ...")
    hooked = extract_hooked_apis(capemon_dir)
    print(f"  -> {len(hooked)} hooks found")

    print(f"Scanning PE import tables: {poc_dir} ...")
    api_to_dlls, file_count = extract_imported_apis(poc_dir)
    poc_apis = set(api_to_dlls.keys())
    print(f"  -> {file_count} .exe files scanned")
    print(f"  -> {len(poc_apis)} unique Windows APIs imported")

    unhooked_apis = sorted(poc_apis - hooked)
    hooked_in_poc = poc_apis & hooked
    coverage = len(hooked_in_poc) / len(poc_apis) if poc_apis else 0.0

    # Group unhooked by DLL
    by_dll: dict[str, list[str]] = {}
    for api in unhooked_apis:
        for dll in sorted(api_to_dlls[api]):
            by_dll.setdefault(dll, []).append(api)
    for v in by_dll.values():
        v.sort()

    result = {
        "unhooked_count": len(unhooked_apis),
        "unhooked_apis": [
            {"api": api, "dll": sorted(api_to_dlls[api])[0]}
            for api in unhooked_apis
        ],
        "poc_api_count": len(poc_apis),
        "hooked_api_count": len(hooked_in_poc),
        "capemon_hook_total": len(hooked),
        "poc_files": file_count,
        "coverage_rate": round(coverage, 4),
        "by_dll": by_dll,
    }

    out_path = Path(args.output)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nResult written to: {out_path}")
    print(f"  .exe files         : {file_count}")
    print(f"  Imported APIs      : {len(poc_apis)}")
    print(f"  capemon hooks      : {len(hooked)}")
    print(f"  Covered by hook    : {len(hooked_in_poc)} ({coverage:.1%})")
    print(f"  NOT hooked         : {len(unhooked_apis)}")
    if unhooked_apis:
        print("\nUnhooked APIs (by DLL):")
        for dll, apis in sorted(by_dll.items()):
            print(f"  [{dll}]")
            for api in apis:
                print(f"    - {api}")


if __name__ == "__main__":
    main()
