
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

/* >>> AUTOHOOK_pa_alk_132_printer_presence_checker BEGIN <<< */
// -> hook_com.c に追加 | category="com" | winapi:Print Spooler
// REVIEW: 引数 pPrinterEnum: 型 LPBYTE はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pcbNeeded: 型 LPDWORD はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pcReturned: 型 LPDWORD はログ指定子を自動決定できず(構造体等)。手動検討
HOOKDEF(BOOL, WINAPI, EnumPrintersA, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD Flags,
	_In_ LPSTR Name,
	_In_ DWORD Level,
	_Out_ LPBYTE pPrinterEnum,
	_In_ DWORD cbBuf,
	_Out_ LPDWORD pcbNeeded,
	_Out_ LPDWORD pcReturned
) {
	BOOL ret;
	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	LOQ_bool("com", "isii", "Flags", Flags, "Name", Name, "Level", Level, "Buf", cbBuf);
	return ret;
}
/* >>> AUTOHOOK_pa_alk_132_printer_presence_checker END <<< */

