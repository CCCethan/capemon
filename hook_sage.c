/*
 * hook_sage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 *
 * Hooks for APIs already present in hook_reg.c / hook_file.c / hook_wmi.c /
 * hook_sleep.c / hook_misc.c / hook_process.c are intentionally omitted here
 * to avoid duplicate New_* definitions; their SAGE logic must be merged into
 * the respective existing hook.
 */
#include "hooking.h"
#include <setupapi.h>
#include <shellapi.h>
#include <winspool.h>
#include <shlobj.h>

HOOKDEF(BOOL, WINAPI, PathFileExistsA,
    LPCSTR pszPath)
{
    BOOL result = Old_PathFileExistsA(pszPath);
    if (pszPath && strstr(pszPath, "ProgramFiles\\7-Zip"))
        result = FALSE;
    return result;
}

HOOKDEF(BOOL, WINAPI, IsProcessorFeaturePresent,
    DWORD ProcessorFeature)
{
    BOOL result = Old_IsProcessorFeaturePresent(ProcessorFeature);
    if (ProcessorFeature == PF_VIRT_FIRMWARE_ENABLED) return FALSE;
    return result;
}

HOOKDEF(BOOL, WINAPI, GetPwrCapabilities,
    PSYSTEM_POWER_CAPABILITIES lpSystemPowerCapabilities)
{
    BOOL result = Old_GetPwrCapabilities(lpSystemPowerCapabilities);
    if (result && lpSystemPowerCapabilities) {
        lpSystemPowerCapabilities->SystemS1 = TRUE;
        lpSystemPowerCapabilities->SystemS2 = TRUE;
        lpSystemPowerCapabilities->SystemS3 = TRUE;
        lpSystemPowerCapabilities->SystemS4 = TRUE;
        lpSystemPowerCapabilities->ThermalControl = TRUE;
    }
    return result;
}

HOOKDEF(BOOL, WINAPI, EnumPrintersA,
    DWORD Flags,
    LPSTR Name,
    DWORD Level,
    LPBYTE pPrinterEnum,
    DWORD cbBuf,
    LPDWORD pcbNeeded,
    LPDWORD pcReturned)
{
    BOOL result = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
    if (pPrinterEnum && pcbNeeded && pcReturned) {
        const char *printer = "HP LaserJet";
        SIZE_T nameLen = strlen(printer) + 1;
        SIZE_T needed = sizeof(PRINTER_INFO_1A) + nameLen * 3;
        *pcbNeeded = (DWORD)needed;
        if (cbBuf >= needed) {
            PRINTER_INFO_1A *info = (PRINTER_INFO_1A *)pPrinterEnum;
            char *p = (char *)(info + 1);
            info->Flags = 0;
            info->pDescription = p; strcpy(p, printer); p += nameLen;
            info->pName        = p; strcpy(p, printer); p += nameLen;
            info->pComment     = p; strcpy(p, printer);
            *pcReturned = 1;
            result = TRUE;
        } else {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            result = FALSE;
        }
    }
    return result;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileA,
    LPCSTR lpFileName,
    LPWIN32_FIND_DATAA lpFindFileData)
{
    HANDLE h = Old_FindFirstFileA(lpFileName, lpFindFileData);
    if (h != INVALID_HANDLE_VALUE && lpFindFileData && lpFileName) {
        if (strstr(lpFileName, "User Pinned\\TaskBar") != NULL) {
            lstrcpyA(lpFindFileData->cFileName, "FakeApp.lnk");
            lpFindFileData->cFileName[sizeof(lpFindFileData->cFileName)-1] = '\0';
            lpFindFileData->cAlternateFileName[0] = '\0';
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
            lpFindFileData->ftCreationTime.dwLowDateTime  = 0;
            lpFindFileData->ftCreationTime.dwHighDateTime = 0;
            lpFindFileData->ftLastAccessTime.dwLowDateTime  = 0;
            lpFindFileData->ftLastAccessTime.dwHighDateTime = 0;
            lpFindFileData->ftLastWriteTime.dwLowDateTime  = 0;
            lpFindFileData->ftLastWriteTime.dwHighDateTime = 0;
            lpFindFileData->nFileSizeLow  = 0;
            lpFindFileData->nFileSizeHigh = 0;
        }
    }
    return h;
}

HOOKDEF(BOOL, WINAPI, FindNextFileA,
    HANDLE hFindFile,
    LPWIN32_FIND_DATAA lpFindFileData)
{
    BOOL result = Old_FindNextFileA(hFindFile, lpFindFileData);
    static const char *fake[] = {"Chrome.lnk", "Notepad.lnk", "Edge.lnk", "Explorer.lnk", "Calc.lnk"};
    enum { MAX_HANDLES = 16 };
    static struct { HANDLE h; int idx; } tbl[MAX_HANDLES];
    int i;
    for (i = 0; i < MAX_HANDLES; ++i)
        if (tbl[i].h == hFindFile) break;
    if (i == MAX_HANDLES)
        for (i = 0; i < MAX_HANDLES; ++i)
            if (tbl[i].h == NULL) { tbl[i].h = hFindFile; tbl[i].idx = 0; break; }
    if (!result && GetLastError() == ERROR_NO_MORE_FILES) {
        int cur = tbl[i].idx;
        if (cur < 5 && cur < (int)(sizeof(fake)/sizeof(fake[0]))) {
            ZeroMemory(lpFindFileData, sizeof(*lpFindFileData));
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
            lstrcpyA(lpFindFileData->cFileName, fake[cur]);
            tbl[i].idx++;
            result = TRUE;
        } else {
            tbl[i].h = NULL;
            SetLastError(ERROR_NO_MORE_FILES);
            result = FALSE;
        }
    }
    return result;
}

HOOKDEF(BOOL, WINAPI, FindClose,
    HANDLE hFindFile)
{
    Old_FindClose(hFindFile);
    return TRUE;
}

HOOKDEF(BOOL, WINAPI, EnumServicesStatusExA,
    SC_HANDLE hSCManager,
    SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle,
    LPCSTR pszGroupName)
{
    BOOL result = Old_EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState,
                      lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned,
                      lpResumeHandle, pszGroupName);
    if (result && lpServices && lpServicesReturned && pcbBytesNeeded) {
        DWORD count = *lpServicesReturned;
        DWORD write = 0;
        DWORD entrySize = (InfoLevel == SC_ENUM_PROCESS_INFO)
                          ? sizeof(ENUM_SERVICE_STATUS_PROCESS)
                          : sizeof(ENUM_SERVICE_STATUS);
        const char *vm[] = {"VBoxGuest", "vmci", "vmhgfs", "vmtoolsd"};
        for (DWORD i = 0; i < count; ++i) {
            BYTE  *src  = lpServices + i * entrySize;
            LPSTR  name = (InfoLevel == SC_ENUM_PROCESS_INFO)
                          ? ((ENUM_SERVICE_STATUS_PROCESS *)src)->lpServiceName
                          : ((ENUM_SERVICE_STATUS *)src)->lpServiceName;
            int hide = 0;
            for (size_t j = 0; j < sizeof(vm)/sizeof(vm[0]); ++j)
                if (name && lstrcmpA(name, vm[j]) == 0) { hide = 1; break; }
            if (!hide) {
                BYTE *dst = lpServices + write * entrySize;
                if (dst != src) RtlMoveMemory(dst, src, entrySize);
                ++write;
            }
        }
        *lpServicesReturned = write;
        *pcbBytesNeeded     = write * entrySize;
    }
    return result;
}

HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus,
    LPSYSTEM_POWER_STATUS lpSystemPowerStatus)
{
    BOOL result = Old_GetSystemPowerStatus(lpSystemPowerStatus);
    if (lpSystemPowerStatus) {
        if (lpSystemPowerStatus->BatteryLifePercent == 255)
            lpSystemPowerStatus->BatteryLifePercent = 75;
        if (lpSystemPowerStatus->ACLineStatus == 255)
            lpSystemPowerStatus->ACLineStatus = 1;
    }
    return result;
}

HOOKDEF(DWORD, WINAPI, GetFileAttributesW,
    LPCWSTR lpFileName)
{
    DWORD result = Old_GetFileAttributesW(lpFileName);
    if (result == INVALID_FILE_ATTRIBUTES && lpFileName) {
        WCHAR user[MAX_PATH];
        DWORD ulen = GetEnvironmentVariableW(L"USERNAME", user, MAX_PATH);
        if (ulen && ulen < MAX_PATH) {
            WCHAR prefix[MAX_PATH];
            wsprintfW(prefix,
                L"C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\",
                user);
            size_t plen = wcslen(prefix);
            if (wcsncmp(lpFileName, prefix, plen) == 0)
                result = FILE_ATTRIBUTE_NORMAL;
        }
    }
    return result;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderPathA,
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPSTR pszPath)
{
    HRESULT hr = Old_SHGetFolderPathA(hwndOwner, nFolder, hToken, dwFlags, pszPath);
    if (SUCCEEDED(hr) && pszPath)
        lstrcpyA(pszPath, "C:\\Sandbox\\Downloads");
    return hr;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinA,
    LPCSTR pszRootPath,
    SHQUERYRBINFO *pSHQueryRBInfo)
{
    HRESULT result = Old_SHQueryRecycleBinA(pszRootPath, pSHQueryRBInfo);
    if (SUCCEEDED(result) && pSHQueryRBInfo)
        if (pSHQueryRBInfo->i64NumItems < 200ULL)
            pSHQueryRBInfo->i64NumItems = 200ULL;
    return result;
}

HOOKDEF(BOOL, WINAPI, SetupDiEnumDeviceInfo,
    HDEVINFO DeviceInfoSet,
    DWORD MemberIndex,
    PSP_DEVINFO_DATA DeviceInfoData)
{
    BOOL result = Old_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);
    if (MemberIndex < 10) {
        result = TRUE;
        if (DeviceInfoData) {
            DeviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
            ZeroMemory(&DeviceInfoData->ClassGuid, sizeof(GUID));
            DeviceInfoData->DevInst  = MemberIndex;
            DeviceInfoData->Reserved = 0;
        }
    }
    return result;
}

HOOKDEF(BOOL, WINAPI, GetFileAttributesExW,
    LPCWSTR lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation)
{
    BOOL result = Old_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    if (lpFileName && lstrcmpW(lpFileName, L"C:\\Windows\\System32\\winevt\\Logs\\System.evtx") == 0) {
        if (fInfoLevelId == GetFileExInfoStandard && lpFileInformation) {
            WIN32_FILE_ATTRIBUTE_DATA *p = (WIN32_FILE_ATTRIBUTE_DATA *)lpFileInformation;
            p->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
            p->ftCreationTime.dwLowDateTime  = 0;
            p->ftCreationTime.dwHighDateTime = 0;
            p->ftLastAccessTime = p->ftCreationTime;
            p->ftLastWriteTime  = p->ftCreationTime;
            p->nFileSizeHigh = 0;
            p->nFileSizeLow  = 0x00100000;
        }
        result = TRUE;
    }
    return result;
}

HOOKDEF(VOID, WINAPI, GetNativeSystemInfo,
    LPSYSTEM_INFO lpSystemInfo)
{
    Old_GetNativeSystemInfo(lpSystemInfo);
    if (lpSystemInfo) lpSystemInfo->dwNumberOfProcessors = 8;
}

HOOKDEF(BOOL, WINAPI, EnumProcesses,
    DWORD *lpidProcess,
    DWORD cb,
    LPDWORD lpcbNeeded)
{
    BOOL result = Old_EnumProcesses(lpidProcess, cb, lpcbNeeded);
    if (result && lpcbNeeded && lpidProcess) {
        DWORD count = *lpcbNeeded / sizeof(DWORD);
        if (count < 100) {
            DWORD target   = 100;
            DWORD maxBytes = target * sizeof(DWORD);
            if (cb >= maxBytes) {
                for (DWORD i = count; i < target; ++i) lpidProcess[i] = 0;
                *lpcbNeeded = maxBytes;
            } else {
                DWORD possible = cb / sizeof(DWORD);
                for (DWORD i = count; i < possible; ++i) lpidProcess[i] = 0;
                *lpcbNeeded = possible * sizeof(DWORD);
            }
        }
    }
    return result;
}

HOOKDEF(DWORD, WINAPI, GetEnvironmentVariableW,
    LPCWSTR lpName,
    LPWSTR lpBuffer,
    DWORD nSize)
{
    DWORD result = Old_GetEnvironmentVariableW(lpName, lpBuffer, nSize);
    if (lpName && lstrcmpW(lpName, L"ProgramFiles") == 0) {
        static const WCHAR fake[] = L"C:\\Program Files\\FakeEnv";
        DWORD needed = (DWORD)lstrlenW(fake) + 1;
        if (!lpBuffer || nSize < needed)
            result = needed;
        else {
            lstrcpynW(lpBuffer, fake, nSize);
            result = needed - 1;
        }
    }
    return result;
}

HOOKDEF(BOOL, WINAPI, QueryServiceConfigA,
    SC_HANDLE hService,
    LPQUERY_SERVICE_CONFIGA lpServiceConfig,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded)
{
    BOOL result = Old_QueryServiceConfigA(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);
    if (result && lpServiceConfig && lpServiceConfig->lpBinaryPathName) {
        char sysRoot[MAX_PATH];
        DWORD len = GetEnvironmentVariableA("SystemRoot", sysRoot, MAX_PATH);
        if (len && len < MAX_PATH) {
            char newPath[MAX_PATH];
            wsprintfA(newPath, "%s\\System32\\svchost.exe", sysRoot);
            if (strncmp(lpServiceConfig->lpBinaryPathName, sysRoot, len) != 0)
                if (strlen(newPath) + 1 <= cbBufSize)
                    strcpy(lpServiceConfig->lpBinaryPathName, newPath);
        }
    }
    return result;
}

HOOKDEF(BOOL, WINAPI, ProcessIdToSessionId,
    DWORD dwProcessId,
    DWORD *pSessionId)
{
    BOOL result = Old_ProcessIdToSessionId(dwProcessId, pSessionId);
    DWORD consoleId = 0;
    Old_ProcessIdToSessionId(GetCurrentProcessId(), &consoleId);
    if (pSessionId) *pSessionId = consoleId;
    return result;
}

HOOKDEF(BOOL, WINAPI, QueryPerformanceCounter,
    LARGE_INTEGER *lpPerformanceCount)
{
    static LARGE_INTEGER fake;
    static BOOL initialized = FALSE;
    if (!initialized) {
        if (lpPerformanceCount && Old_QueryPerformanceCounter(lpPerformanceCount)) {
            fake = *lpPerformanceCount;
            initialized = TRUE;
            return TRUE;
        }
        return FALSE;
    }
    if (lpPerformanceCount) {
        fake.QuadPart += 10000;
        *lpPerformanceCount = fake;
    }
    return TRUE;
}

HOOKDEF(BOOL, WINAPI, QueryPerformanceFrequency,
    LARGE_INTEGER *lpFrequency)
{
    BOOL result = Old_QueryPerformanceFrequency(lpFrequency);
    if (lpFrequency) lpFrequency->QuadPart = 10000000LL;
    return result;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileW,
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData)
{
    HANDLE h = Old_FindFirstFileW(lpFileName, lpFindFileData);
    if (lpFileName && wcscmp(lpFileName,
            L"C:\\Users\\TestUser\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar\\*") == 0
        && h == INVALID_HANDLE_VALUE) {
        static const WCHAR *names[] = {L"App1.lnk", L"App2.lnk", L"App3.lnk", L"App4.lnk", L"App5.lnk"};
        if (lpFindFileData) {
            ZeroMemory(lpFindFileData, sizeof(*lpFindFileData));
            wcscpy(lpFindFileData->cFileName, names[0]);
            lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        SetLastError(0);
        return (HANDLE)0xDEADBEEF;
    }
    return h;
}
