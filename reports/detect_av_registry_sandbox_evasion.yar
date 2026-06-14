/*
 * YARA rules for detecting sandbox evasion via AV product registry enumeration
 *
 * Detection target:
 *   Executables that query HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av
 *   to count registered antivirus products and use the count as a threshold
 *   to distinguish user environments from sandboxes.
 *
 * Reference:  reports/938_report.json
 * Sample SHA256: 368ea7134adaab1b736b049fb58afbd935bef8f0151bc515360613d8966a80cc
 *
 * Constraint: NtWriteFile intent/log strings are intentionally excluded.
 *             All strings used here are functional data strings (registry paths,
 *             API names, RTTI symbols, family-specific artifacts) that are NOT
 *             written via NtWriteFile.
 */

import "pe"

/* ------------------------------------------------------------------ *
 * Rule 1 (Generic / Broadest)
 * Detects the core technique: enumerate Security Center AV subkeys and
 * query each provider's displayName to count registered AV products.
 * Requires the registry path + displayName + two registry API imports.
 * ------------------------------------------------------------------ */
rule Detect_SecurityCenter_AV_Enumeration_SandboxEvasion
{
    meta:
        description  = "Detects sandbox evasion via HKLM Security Center AV provider registry enumeration"
        author       = "Generated from 938_report.json"
        date         = "2026-06-15"
        technique    = "T1012 - Query Registry"
        score        = 70
        reference    = "HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av"

    strings:
        // Registry path used to enumerate all registered AV providers (GUID subkeys)
        $reg_av_path        = "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av" wide ascii

        // Value name queried under each AV-provider GUID subkey to obtain the product name
        $reg_displayname    = "displayName" wide ascii

        // Registry API exports that implement the enumeration pattern
        $imp_RegEnumKeyExW    = "RegEnumKeyExW"    ascii
        $imp_RegOpenKeyExW    = "RegOpenKeyExW"    ascii
        $imp_RegQueryValueExW = "RegQueryValueExW" ascii

    condition:
        uint16(0) == 0x5A4D          // PE: MZ header
        and $reg_av_path
        and $reg_displayname
        and 2 of ($imp_*)
}

/* ------------------------------------------------------------------ *
 * Rule 2 (Medium specificity)
 * Same technique, but also requires the ProviderName value query and
 * the RTTI type-name of the C++ checker class (.?AVWmiAvProductChecker@@).
 * Catches compiled C++ variants that retained RTTI.
 * ------------------------------------------------------------------ */
rule Detect_WmiAvProductChecker_SandboxEvasion
{
    meta:
        description = "Detects WmiAvProductChecker C++ class performing AV-count-based sandbox detection"
        author      = "Generated from 938_report.json"
        date        = "2026-06-15"
        technique   = "T1012 - Query Registry"
        score       = 80

    strings:
        // RTTI mangled type name for the checker class
        $rtti_checker       = ".?AVWmiAvProductChecker@@" ascii

        // Core AV-enumeration registry path
        $reg_av_path        = "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av" wide ascii

        // Value names read from each provider subkey
        $reg_displayname    = "displayName"  wide ascii
        $reg_providername   = "ProviderName" wide ascii

        // Registry enumeration API (subset check — not all three may be statically imported)
        $imp_enum           = "RegEnumKeyExW"    ascii
        $imp_query          = "RegQueryValueExW" ascii

    condition:
        uint16(0) == 0x5A4D
        and $rtti_checker
        and $reg_av_path
        and 1 of ($reg_displayname, $reg_providername)
        and 1 of ($imp_enum, $imp_query)
}

/* ------------------------------------------------------------------ *
 * Rule 3 (Medium specificity + network)
 * AV-count evasion combined with WinHTTP C2 activity.
 * The malware only executes its payload (WinHTTP requests) when the AV
 * count meets the threshold — the presence of both patterns together
 * strongly indicates conditional payload execution after sandbox bypass.
 * ------------------------------------------------------------------ */
rule Detect_AVCount_Evasion_WinHTTP_C2
{
    meta:
        description = "Detects AV product count sandbox evasion with WinHTTP C2 payload"
        author      = "Generated from 938_report.json"
        date        = "2026-06-15"
        technique   = "T1012 - Query Registry, T1071.001 - Application Layer Protocol: Web Protocols"
        score       = 75

    strings:
        // AV provider enumeration registry key
        $reg_av_path        = "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av" wide ascii

        // Registry enumeration import
        $imp_RegEnumKeyExW  = "RegEnumKeyExW" ascii

        // WinHTTP imports used for C2 after successful sandbox bypass
        $imp_wh_open        = "WinHttpOpen"        ascii
        $imp_wh_connect     = "WinHttpConnect"     ascii
        $imp_wh_send        = "WinHttpSendRequest" ascii
        $imp_wh_recv        = "WinHttpReceiveResponse" ascii

    condition:
        uint16(0) == 0x5A4D
        and $reg_av_path
        and $imp_RegEnumKeyExW
        and 2 of ($imp_wh_*)
}

/* ------------------------------------------------------------------ *
 * Rule 4 (Narrow / Family-specific)
 * Detects the "ylab-evidence" malware family by its unique HTTP
 * User-Agent string, its family-specific result-logging registry paths,
 * and the sandbox log artifact — all combined with the AV-enumeration
 * registry path.
 * ------------------------------------------------------------------ */
rule Detect_YLab_Evidence_AV_Sandbox_Evasion_Family
{
    meta:
        description = "Detects ylab-evidence family: AV sandbox evasion + evidence logging artifacts"
        author      = "Generated from 938_report.json"
        date        = "2026-06-15"
        technique   = "T1012 - Query Registry, T1082 - System Information Discovery"
        score       = 90
        sha256      = "368ea7134adaab1b736b049fb58afbd935bef8f0151bc515360613d8966a80cc"

    strings:
        // Core AV-enumeration registry path (mandatory)
        $reg_av_path        = "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av" wide ascii

        // Family-specific HTTP User-Agent used in WinHTTP requests
        $ua_string          = "ylab-evidence/1.0" ascii

        // Family-specific result-recording registry paths
        $reg_sandbox_res    = "Software\\ylab\\results\\Sandbox\\"  wide ascii
        $reg_user_res       = "Software\\ylab\\results\\RealUser\\" wide ascii

        // File artifact created when sandbox branch is taken
        $file_sandbox_log   = "sandbox_evidence.log" wide ascii

    condition:
        uint16(0) == 0x5A4D
        and $reg_av_path
        and (
            $ua_string
            or ($reg_sandbox_res and $reg_user_res)
            or $file_sandbox_log
        )
}

/* ------------------------------------------------------------------ *
 * Rule 5 (Imphash — exact build match)
 * Matches the exact compiled binary from the analysis report.
 * High precision, zero tolerance for recompilation.
 * Use in conjunction with broader rules for context.
 * ------------------------------------------------------------------ */
rule Detect_YLab_AV_Evasion_Exact_Build
{
    meta:
        description = "Exact imphash match for ylab AV-enumeration sandbox-evasion binary"
        author      = "Generated from 938_report.json"
        date        = "2026-06-15"
        score       = 95
        sha256      = "368ea7134adaab1b736b049fb58afbd935bef8f0151bc515360613d8966a80cc"
        imphash     = "5423e7cfdb2d1e055f417ce3b80552e9"

    condition:
        uint16(0) == 0x5A4D
        and pe.imphash() == "5423e7cfdb2d1e055f417ce3b80552e9"
}
