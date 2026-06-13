Generate a complete capemon hook for the following API:

$ARGUMENTS

The input format is: `<ApiName> <library> <category> "<evasion description>"`
- ApiName: the Windows API function name (e.g. GetSystemInfo)
- library: the DLL without extension (e.g. kernel32, ntdll, wbemprox)
- category: log category string (e.g. misc, system, filesystem, process, network, registry, synchronization, device)
- evasion description: what the malware does with this API and why it needs to be hooked/spoofed

---

## capemon Hook System Reference

Every hook requires changes to THREE places. Output exactly three labeled fenced C code blocks, in this order:

### Block 1 — hooks.h (HOOKDEF declaration)
### Block 2 — hooks.c (registration line in full_hooks[])
### Block 3 — hook_<category>.c (New_<ApiName> implementation)

---

## HOOKDEF Macro

```c
// In hooking.h — expands to Old_ function pointer + New_ implementation signature:
#define HOOKDEF(return_value, calling_convention, apiname, ...) \
    return_value (calling_convention *Old_##apiname)(__VA_ARGS__); \
    return_value calling_convention New_##apiname(__VA_ARGS__)
```

Declaration in hooks.h (semicolon-terminated, no body):
```c
HOOKDEF(ReturnType, CallingConvention, ApiName,
    _In_    PARAM_TYPE  param1,
    _Out_   PARAM_TYPE  param2
);
```

Common SAL annotations: `_In_`, `_Out_`, `_Inout_`, `_In_opt_`, `_Out_opt_`, `_In_reads_bytes_(n)`

---

## Registration in hooks.c

```c
// Inside full_hooks[] array, before the closing };
HOOK(library, ApiName),
// or for COM vtable / special hooks:
HOOK_SPECIAL(library, ApiName),
```

---

## LOQ_ Macros (pick based on return type)

```c
LOQ_ntstatus(cat, fmt, ...)   // NTSTATUS — success when NT_SUCCESS(ret)
LOQ_hresult(cat, fmt, ...)    // HRESULT  — success when ret == S_OK
LOQ_bool(cat, fmt, ...)       // BOOL     — success when ret != FALSE
LOQ_void(cat, fmt, ...)       // void     — always success (need `int ret = 0;` at top)
LOQ_handle(cat, fmt, ...)     // HANDLE   — success when ret != NULL && ret != INVALID_HANDLE_VALUE
LOQ_nonnull(cat, fmt, ...)    // pointer  — success when ret != NULL
LOQ_zero(cat, fmt, ...)       // int      — success when ret == 0
LOQ_nonzero(cat, fmt, ...)    // int      — success when ret != 0
```

## Format Specifiers

| Specifier | C type          | Meaning                                      |
|-----------|-----------------|----------------------------------------------|
| `s`       | `char *`        | zero-terminated ASCII string                 |
| `u`       | `wchar_t *`     | zero-terminated Unicode string (also BSTR)   |
| `U`       | `int, wchar_t*` | Unicode string with explicit length          |
| `f`       | `char *`        | ASCII filename (normalized)                  |
| `F`       | `wchar_t *`     | Unicode filename (normalized)                |
| `i`       | `int`           | signed integer                               |
| `l`       | `long`          | long integer                                 |
| `p`       | `void *`        | pointer / address                            |
| `P`       | `void **`       | pointer to handle                            |
| `b`       | `int, void *`   | binary blob with size                        |
| `B`       | `int*, void *`  | binary blob (size from pointer)              |
| `n`       | `VARIANT *`     | VARIANT value (auto-typed)                   |
| `o`       | `UNICODE_STRING*`| UNICODE_STRING                              |
| `O`       | `OBJECT_ATTRIBUTES*` | filename via OBJECT_ATTRIBUTES          |
| `K`       | `OBJECT_ATTRIBUTES*` | registry key via OBJECT_ATTRIBUTES      |
| `h`       | `DWORD`         | flags/hex value                              |
| `r`/`R`   | type, int, str  | registry value (r=ANSI, R=Unicode)           |

LOQ_ call format: `LOQ_variant("category", "key1_fmt key2_fmt", "Key1", val1, "Key2", val2);`
Empty log: `LOQ_void("misc", "");`

---

## Key Implementation Rules

1. **Always call `Old_ApiName(...)` first** (preserves original return value), unless it's a full emulation (`HOOK_EMULATE`).

2. **Spoofing/evasion guard**: any code that changes output values MUST be guarded:
   ```c
   if (!g_config.no_stealth) {
       // modify the output here
   }
   ```

3. **Preserve error state** around spoofing with lasterror_t (use when there's risk of clobbering GetLastError):
   ```c
   lasterror_t lasterror;
   get_lasterrors(&lasterror);
   // ... spoof code ...
   set_lasterrors(&lasterror);
   ```

4. **COM/vtable hooks**: first parameter is always `PVOID _this`, call original via vtable:
   ```c
   ret = Old_WMI_Get(_this, ...);
   // direct vtable call for sub-operations:
   ((IWbemClassObject*)_this)->lpVtbl->Get(pObj, L"__CLASS", 0, &var, NULL, NULL);
   ```

5. **void-returning hooks** need `int ret = 0;` at the top so LOQ_ macros compile.

6. **`__try/__except`** when touching potentially-invalid COM objects:
   ```c
   __try { ... } __except (EXCEPTION_EXECUTE_HANDLER) { ... }
   ```

---

## Few-Shot Examples

### Example A — Minimal WINAPI hook with spoofing (GetSystemInfo)

**hooks.h:**
```c
HOOKDEF(void, WINAPI, GetSystemInfo,
    __out LPSYSTEM_INFO lpSystemInfo
);
```

**hooks.c:**
```c
HOOK(kernel32, GetSystemInfo),
```

**hook_misc.c:**
```c
HOOKDEF(void, WINAPI, GetSystemInfo,
    __out LPSYSTEM_INFO lpSystemInfo
) {
    int ret = 0;

    Old_GetSystemInfo(lpSystemInfo);

    if (!g_config.no_stealth && lpSystemInfo->dwNumberOfProcessors < g_config.spoofed_cpu_count)
        lpSystemInfo->dwNumberOfProcessors = g_config.spoofed_cpu_count;

    LOQ_void("misc", "");

    return;
}
```

---

### Example B — COM vtable hook with class lookup + spoofing + filtered logging (WMI_Get)

**hooks.h:**
```c
HOOKDEF(HRESULT, WINAPI, WMI_Get,
    _In_        PVOID   _this,
    _In_        LPCWSTR wszName,
    _In_        LONG    lFlags,
    _Out_       VARIANT *pVal,
    _Out_opt_   CIMTYPE *pType,
    _Out_opt_   LONG    *plFlavor
);
```

**hooks.c:**
```c
HOOK_SPECIAL(wbemprox, WMI_Get),
```

**hook_wmi.c:**
```c
HOOKDEF(HRESULT, WINAPI, WMI_Get,
    _In_        PVOID   _this,
    _In_        LPCWSTR wszName,
    _In_        LONG    lFlags,
    _Out_       VARIANT *pVal,
    _Out_opt_   CIMTYPE *pType,
    _Out_opt_   LONG    *plFlavor
) {
    HRESULT ret;
    WCHAR szClassName[256] = L"";
    if (wszName && _wcsicmp(wszName, L"__CLASS") != 0) {
        VARIANT classVariant;
        VariantInit(&classVariant);
        IWbemClassObject* pWmiObject = (IWbemClassObject*)_this;
        HRESULT hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
        if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR) {
            wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);
        }
        VariantClear(&classVariant);
    }

    ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);
    SpoofWmiData(szClassName, wszName, pVal);

    if (!ret && !g_config.full_logs && wszName) {
        if (!_wcsicmp(wszName, L"__CLASS") || !_wcsicmp(wszName, L"__GENUS"))
            return ret;
    }

    LOQ_hresult("system", "unu", "Name", wszName, "Value", pVal, "Class", szClassName);
    return ret;
}
```

---

### Example C — COM hook with lasterror preservation + __try/__except (WMI_Next)

**hooks.h:**
```c
HOOKDEF(HRESULT, WINAPI, WMI_Next,
    _In_        PVOID   _this,
    _In_        LONG    lFlags,
    _Out_       BSTR    *strName,
    _Out_       VARIANT *pVal,
    _Out_opt_   CIMTYPE *pType,
    _Out_opt_   LONG    *plFlavor
);
```

**hooks.c:**
```c
HOOK_SPECIAL(wbemprox, WMI_Next),
```

**hook_wmi.c:**
```c
HOOKDEF(HRESULT, WINAPI, WMI_Next,
    _In_        PVOID   _this,
    _In_        LONG    lFlags,
    _Out_       BSTR    *strName,
    _Out_       VARIANT *pVal,
    _Out_opt_   CIMTYPE *pType,
    _Out_opt_   LONG    *plFlavor
) {
    HRESULT ret = Old_WMI_Next(_this, lFlags, strName, pVal, pType, plFlavor);

    if (ret != S_OK || !pVal || pVal->vt == VT_NULL || !strName || !*strName)
        return ret;

    lasterror_t lasterror;
    get_lasterrors(&lasterror);
    VARIANT classVariant;
    VariantInit(&classVariant);

    __try {
        IWbemClassObject* pWmiObject = (IWbemClassObject*)_this;
        HRESULT hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
        WCHAR szClassName[256] = L"";
        if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR)
            wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);
        SpoofWmiData(szClassName, *strName, pVal);
        LOQ_hresult("system", "unu", "Name", *strName, "Value", pVal, "Class", szClassName);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOQ_hresult("system", "un", "Name", *strName, "Value", pVal);
    }

    VariantClear(&classVariant);
    set_lasterrors(&lasterror);
    return ret;
}
```

---

## g_config stealth fields (for reference)

- `g_config.no_stealth` — when non-zero, skip all spoofing (sandbox testing mode)
- `g_config.spoofed_cpu_count` — number of logical CPUs to report
- `g_config.full_logs` — when set, log everything including filtered fields

---

Now generate the three code blocks for the API described in the arguments above.
Use the most appropriate LOQ_ variant for the return type.
If the evasion description involves reporting false hardware/system values, add spoofing logic guarded by `if (!g_config.no_stealth)`.
Output ONLY the three labeled fenced C code blocks — no prose before or after.
