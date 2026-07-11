
#include "hooking.h"
#include "log.h"
#include "CAPE\CAPE.h"
#include <Wbemidl.h>

BOOL ContainsNamespace(const wchar_t* resource, const wchar_t* target) {
	/*
	* Basically case insensitive strstr except we don't care about forward/backward slashes.
	* Used for namespace checks in WbemLocator_ConnectServer
	*/
	if (!resource || !target) {
		return FALSE;
	}

	// Iterate through the resource string to find a starting match point
	for (; *resource; ++resource) {
		const wchar_t* h = resource; // Haystack pointer
		const wchar_t* n = target;   // Needle pointer

		// Attempt to match the target string from the current position
		while (*h && *n) {
			BOOL isSlashMatch = (*h == L'/' || *h == L'\\') && (*n == L'/' || *n == L'\\');
			if (isSlashMatch || (towlower(*h) == towlower(*n))) {
				h++;
				n++;
			}
			else {
				// Break on mismatch
				break;
			}
		}

		// If we reached the end of the target string, it's a successful match
		if (*n == L'\0') {
			return TRUE;
		}
	}

	return FALSE;
}

__declspec(thread) BOOL bHookViaWbemLocator;
HOOKDEF(HRESULT, WINAPI, WbemLocator_ConnectServer,
	_In_	PVOID			_this,
	_In_	const BSTR		strNetworkResource,
	_In_	const BSTR		strUser,
	_In_	const BSTR		strPassword,
	_In_	const BSTR		strLocale,
	_In_	long			lSecurityFlags,
	_In_	const BSTR		strAuthority,
	_In_	IWbemContext	*pCtx,
	_Out_	IWbemServices	**ppNamespace
) {
	HRESULT ret;
	ret = Old_WbemLocator_ConnectServer(_this, strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);

	if (ret == S_OK && (
		ContainsNamespace(strNetworkResource, L"ROOT\\CIMV2") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\SecurityCenter2") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\Microsoft\\Windows\\Defender") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\subscription") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\Microsoft\\Windows\\TaskScheduler")
	)) 
	{
		bHookViaWbemLocator = TRUE;
		set_com_hooks(NULL, NULL, *ppNamespace);
		bHookViaWbemLocator = FALSE;
	}

	LOQ_hresult("com", "uu", "NetworkResource", strNetworkResource, "User", strUser);
	return ret;
}

/* ============================================================================
 * MIRAGE2 ADDED HOOKS -- hook_com.c
 * Auto-generated skeletons from data/api_hook_analysis/unhooked_api_classified.jsonl
 * Added 2026-07-11. Fill in spoofing/filtering logic per API as needed.
 * ============================================================================ */
/* ---- MIRAGE2 REQUIRED TYPE HEADERS ---- */
#include <objbase.h>
#include <shlobj.h>
#include <oleauto.h>

#include <objbase.h>
#include <oleauto.h>
#include <shlobj.h>

HOOKDEF(HRESULT, WINAPI, CoInitialize,
	LPVOID pvReserved
) {
	HRESULT ret = Old_CoInitialize(pvReserved);
	LOQ_hresult("com", "p", "PvReserved", pvReserved);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoInitializeEx,
	LPVOID pvReserved,
	DWORD dwCoInit
) {
	HRESULT ret = Old_CoInitializeEx(pvReserved, dwCoInit);
	LOQ_hresult("com", "pi", "PvReserved", pvReserved, "DwCoInit", dwCoInit);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoInitializeSecurity,
	PSECURITY_DESCRIPTOR pSecDesc,
	LONG cAuthSvc,
	SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	void* pReserved1,
	DWORD dwAuthnLevel,
	DWORD dwImpLevel,
	void* pAuthList,
	DWORD dwCapabilities,
	void* pReserved3
) {
	HRESULT ret = Old_CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
	LOQ_hresult("com", "pippiipip", "PSecDesc", pSecDesc, "CAuthSvc", cAuthSvc, "AsAuthSvc", asAuthSvc, "PReserved1", pReserved1, "DwAuthnLevel", dwAuthnLevel, "DwImpLevel", dwImpLevel, "PAuthList", pAuthList, "DwCapabilities", dwCapabilities, "PReserved3", pReserved3);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoSetProxyBlanket,
	IUnknown* pProxy,
	DWORD dwAuthnSvc,
	DWORD dwAuthzSvc,
	OLECHAR* pServerPrincName,
	DWORD dwAuthnLevel,
	DWORD dwImpLevel,
	RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	DWORD dwCapabilities
) {
	HRESULT ret = Old_CoSetProxyBlanket(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
	LOQ_hresult("com", "piipiiii", "PProxy", pProxy, "DwAuthnSvc", dwAuthnSvc, "DwAuthzSvc", dwAuthzSvc, "PServerPrincName", pServerPrincName, "DwAuthnLevel", dwAuthnLevel, "DwImpLevel", dwImpLevel, "PAuthInfo", pAuthInfo, "DwCapabilities", dwCapabilities);
	return ret;
}

HOOKDEF(void, WINAPI, CoTaskMemFree,
	LPVOID pv
) {
	int ret = 0;
	Old_CoTaskMemFree(pv);
	LOQ_void("com", "p", "Pv", pv);
	return;
}

HOOKDEF(void, WINAPI, CoUninitialize
) {
	int ret = 0;
	Old_CoUninitialize();
	LOQ_void("com", "");
	return;
}

HOOKDEF(HRESULT, WINAPI, CreateBindCtx,
	DWORD reserved,
	LPBC* ppbc
) {
	HRESULT ret = Old_CreateBindCtx(reserved, ppbc);
	LOQ_hresult("com", "ip", "Reserved", reserved, "Ppbc", ppbc);
	return ret;
}

HOOKDEF(PIDLIST_ABSOLUTE, WINAPI, ILCombine,
	PCIDLIST_ABSOLUTE pidl1,
	PCUIDLIST_RELATIVE pidl2
) {
	PIDLIST_ABSOLUTE ret = Old_ILCombine(pidl1, pidl2);
	LOQ_nonnull("com", "pp", "Pidl1", pidl1, "Pidl2", pidl2);
	return ret;
}

HOOKDEF(void, WINAPI, ILFree,
	PIDLIST_RELATIVE pidl
) {
	int ret = 0;
	Old_ILFree(pidl);
	LOQ_void("com", "p", "Pidl", pidl);
	return;
}

HOOKDEF(HRESULT, WINAPI, OleInitialize,
	LPVOID pvReserved
) {
	HRESULT ret = Old_OleInitialize(pvReserved);
	LOQ_hresult("com", "p", "PvReserved", pvReserved);
	return ret;
}

HOOKDEF(void, WINAPI, OleUninitialize
) {
	int ret = 0;
	Old_OleUninitialize();
	LOQ_void("com", "");
	return;
}

HOOKDEF(HRESULT, WINAPI, PropVariantClear,
	PROPVARIANT* pvar
) {
	HRESULT ret = Old_PropVariantClear(pvar);
	LOQ_hresult("com", "p", "Pvar", pvar);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHBindToObject,
	IShellFolder* psf,
	PCUIDLIST_RELATIVE pidl,
	IBindCtx* pbc,
	REFIID riid,
	void** ppv
) {
	HRESULT ret = Old_SHBindToObject(psf, pidl, pbc, riid, ppv);
	LOQ_hresult("com", "pppip", "Psf", psf, "Pidl", pidl, "Pbc", pbc, "Riid", riid, "Ppv", ppv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHCreateItemFromIDList,
	PCIDLIST_ABSOLUTE pidl,
	REFIID riid,
	void** ppv
) {
	HRESULT ret = Old_SHCreateItemFromIDList(pidl, riid, ppv);
	LOQ_hresult("com", "pip", "Pidl", pidl, "Riid", riid, "Ppv", ppv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHCreateItemFromParsingName,
	PCWSTR pszPath,
	IBindCtx* pbc,
	REFIID riid,
	void** ppv
) {
	HRESULT ret = Old_SHCreateItemFromParsingName(pszPath, pbc, riid, ppv);
	LOQ_hresult("com", "upip", "PszPath", pszPath, "Pbc", pbc, "Riid", riid, "Ppv", ppv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHCreateItemWithParent,
	PCIDLIST_ABSOLUTE pidlParent,
	IShellFolder* psfParent,
	PCUITEMID_CHILD pidl,
	REFIID riid,
	void** ppvItem
) {
	HRESULT ret = Old_SHCreateItemWithParent(pidlParent, psfParent, pidl, riid, ppvItem);
	LOQ_hresult("com", "pppip", "PidlParent", pidlParent, "PsfParent", psfParent, "Pidl", pidl, "Riid", riid, "PpvItem", ppvItem);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetDesktopFolder,
	IShellFolder** ppshf
) {
	HRESULT ret = Old_SHGetDesktopFolder(ppshf);
	LOQ_hresult("com", "p", "Ppshf", ppshf);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderLocation,
	HWND hwnd,
	int csidl,
	HANDLE hToken,
	DWORD dwFlags,
	PIDLIST_ABSOLUTE* ppidl
) {
	HRESULT ret = Old_SHGetFolderLocation(hwnd, csidl, hToken, dwFlags, ppidl);
	LOQ_hresult("com", "pipip", "Hwnd", hwnd, "Csidl", csidl, "HToken", hToken, "DwFlags", dwFlags, "Ppidl", ppidl);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderPathA,
	HWND hwnd,
	int csidl,
	HANDLE hToken,
	DWORD dwFlags,
	LPSTR pszPath
) {
	HRESULT ret = Old_SHGetFolderPathA(hwnd, csidl, hToken, dwFlags, pszPath);
	LOQ_hresult("com", "pipis", "Hwnd", hwnd, "Csidl", csidl, "HToken", hToken, "DwFlags", dwFlags, "PszPath", pszPath);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetKnownFolderIDList,
	REFKNOWNFOLDERID rfid,
	DWORD dwFlags,
	HANDLE hToken,
	PIDLIST_ABSOLUTE* ppidl
) {
	HRESULT ret = Old_SHGetKnownFolderIDList(rfid, dwFlags, hToken, ppidl);
	LOQ_hresult("com", "iipp", "Rfid", rfid, "DwFlags", dwFlags, "HToken", hToken, "Ppidl", ppidl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SHGetPathFromIDListA,
	PCIDLIST_ABSOLUTE pidl,
	LPSTR pszPath
) {
	BOOL ret = Old_SHGetPathFromIDListA(pidl, pszPath);
	LOQ_bool("com", "ps", "Pidl", pidl, "PszPath", pszPath);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SHGetPathFromIDListW,
	PCIDLIST_ABSOLUTE pidl,
	LPWSTR pszPath
) {
	BOOL ret = Old_SHGetPathFromIDListW(pidl, pszPath);
	LOQ_bool("com", "pu", "Pidl", pidl, "PszPath", pszPath);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetSpecialFolderLocation,
	HWND hwnd,
	int csidl,
	PIDLIST_ABSOLUTE* ppidl
) {
	HRESULT ret = Old_SHGetSpecialFolderLocation(hwnd, csidl, ppidl);
	LOQ_hresult("com", "pip", "Hwnd", hwnd, "Csidl", csidl, "Ppidl", ppidl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SHGetSpecialFolderPathA,
	HWND hwnd,
	LPSTR pszPath,
	int csidl,
	BOOL fCreate
) {
	BOOL ret = Old_SHGetSpecialFolderPathA(hwnd, pszPath, csidl, fCreate);
	LOQ_bool("com", "psii", "Hwnd", hwnd, "PszPath", pszPath, "Csidl", csidl, "FCreate", fCreate);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHParseDisplayName,
	PCWSTR pszName,
	IBindCtx* pbc,
	PIDLIST_ABSOLUTE* ppidl,
	SFGAOF sfgaoIn,
	SFGAOF* psfgaoOut
) {
	HRESULT ret = Old_SHParseDisplayName(pszName, pbc, ppidl, sfgaoIn, psfgaoOut);
	LOQ_hresult("com", "uppip", "PszName", pszName, "Pbc", pbc, "Ppidl", ppidl, "SfgaoIn", sfgaoIn, "PsfgaoOut", psfgaoOut);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBin,
	LPCWSTR pszRootPath,
	LPSHQUERYRBINFO pSHQueryRBInfo
) {
	HRESULT ret = Old_SHQueryRecycleBin(pszRootPath, pSHQueryRBInfo);
	LOQ_hresult("com", "up", "PszRootPath", pszRootPath, "PSHQueryRBInfo", pSHQueryRBInfo);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinA,
	LPCSTR pszRootPath,
	LPSHQUERYRBINFO pSHQueryRBInfo
) {
	HRESULT ret = Old_SHQueryRecycleBinA(pszRootPath, pSHQueryRBInfo);
	LOQ_hresult("com", "sp", "PszRootPath", pszRootPath, "PSHQueryRBInfo", pSHQueryRBInfo);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinW,
	LPCWSTR pszRootPath,
	LPSHQUERYRBINFO pSHQueryRBInfo
) {
	HRESULT ret = Old_SHQueryRecycleBinW(pszRootPath, pSHQueryRBInfo);
	LOQ_hresult("com", "up", "PszRootPath", pszRootPath, "PSHQueryRBInfo", pSHQueryRBInfo);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayDestroy,
	SAFEARRAY* psa
) {
	HRESULT ret = Old_SafeArrayDestroy(psa);
	LOQ_hresult("com", "p", "Psa", psa);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayGetElement,
	SAFEARRAY* psa,
	LONG* rgIndices,
	void* pv
) {
	HRESULT ret = Old_SafeArrayGetElement(psa, rgIndices, pv);
	LOQ_hresult("com", "ppp", "Psa", psa, "RgIndices", rgIndices, "Pv", pv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayGetLBound,
	SAFEARRAY* psa,
	UINT nDim,
	LONG* plLbound
) {
	HRESULT ret = Old_SafeArrayGetLBound(psa, nDim, plLbound);
	LOQ_hresult("com", "pip", "Psa", psa, "NDim", nDim, "PlLbound", plLbound);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayGetUBound,
	SAFEARRAY* psa,
	UINT nDim,
	LONG* plUbound
) {
	HRESULT ret = Old_SafeArrayGetUBound(psa, nDim, plUbound);
	LOQ_hresult("com", "pip", "Psa", psa, "NDim", nDim, "PlUbound", plUbound);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, StrRetToBufW,
	STRRET* pstr,
	PCUITEMID_CHILD pidl,
	LPWSTR pszBuf,
	UINT cchBuf
) {
	HRESULT ret = Old_StrRetToBufW(pstr, pidl, pszBuf, cchBuf);
	LOQ_hresult("com", "ppui", "Pstr", pstr, "Pidl", pidl, "PszBuf", pszBuf, "CchBuf", cchBuf);
	return ret;
}

HOOKDEF(int, WINAPI, StringFromGUID2,
	REFGUID rguid,
	LPOLESTR lpsz,
	int cchMax
) {
	int ret = Old_StringFromGUID2(rguid, lpsz, cchMax);
	LOQ_nonzero("com", "iui", "Rguid", rguid, "Lpsz", lpsz, "CchMax", cchMax);
	return ret;
}

HOOKDEF(BSTR, WINAPI, SysAllocString,
	const OLECHAR* psz
) {
	BSTR ret = Old_SysAllocString(psz);
	LOQ_nonzero("com", "p", "Psz", psz);
	return ret;
}

HOOKDEF(UINT, WINAPI, SysStringLen,
	BSTR bstr
) {
	UINT ret = Old_SysStringLen(bstr);
	LOQ_nonzero("com", "u", "Bstr", bstr);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, VariantClear,
	VARIANTARG* pvarg
) {
	HRESULT ret = Old_VariantClear(pvarg);
	LOQ_hresult("com", "p", "Pvarg", pvarg);
	return ret;
}

HOOKDEF(void, WINAPI, VariantInit,
	VARIANTARG* pvarg
) {
	int ret = 0;
	Old_VariantInit(pvarg);
	LOQ_void("com", "p", "Pvarg", pvarg);
	return;
}
