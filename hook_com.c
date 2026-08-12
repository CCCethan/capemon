
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

/* >>> AUTOHOOK_mitre_096_smbios_manufacturer_checker BEGIN <<< */
// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pvReserved: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(HRESULT, WINAPI, CoInitializeEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPVOID pvReserved,
	_In_ DWORD dwCoInit
) {
	HRESULT ret;
	ret = Old_CoInitializeEx(pvReserved, dwCoInit);
	LOQ_hresult("com", "pi", "VReserved", pvReserved, "CoInit", dwCoInit);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pSecDesc: 型 PSECURITY_DESCRIPTOR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 asAuthSvc: 型 SOLE_AUTHENTICATION_SERVICE* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pReserved1: 型 void* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pAuthList: 型 void* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pReserved3: 型 void* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HRESULT, WINAPI, CoInitializeSecurity, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ PSECURITY_DESCRIPTOR pSecDesc,
	_In_ LONG cAuthSvc,
	_In_opt_ SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	_In_opt_ void* pReserved1,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ void* pAuthList,
	_In_ DWORD dwCapabilities,
	_In_opt_ void* pReserved3
) {
	HRESULT ret;
	ret = Old_CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
	LOQ_hresult("com", "pippiipip", "SecDesc", pSecDesc, "CAuthSvc", cAuthSvc, "AsAuthSvc", asAuthSvc, "Reserved1", pReserved1, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "AuthList", pAuthList, "Capabilities", dwCapabilities, "Reserved3", pReserved3);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pProxy: 型 IUnknown* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pServerPrincName: 型 OLECHAR* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pAuthInfo: 型 RPC_AUTH_IDENTITY_HANDLE を i(int32)で仮記録。要確認
HOOKDEF(HRESULT, WINAPI, CoSetProxyBlanket, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ IUnknown* pProxy,
	_In_ DWORD dwAuthnSvc,
	_In_ DWORD dwAuthzSvc,
	_In_opt_ OLECHAR* pServerPrincName,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	_In_ DWORD dwCapabilities
) {
	HRESULT ret;
	ret = Old_CoSetProxyBlanket(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
	// [7.5] ServerPrincName は型 OLECHAR* = ワイド文字列(desc「The server principal name」)。
	//       本解析では NULL(COLE_DEFAULT_PRINCIPAL)だが u は NULL 安全なので内容可読化する。
	LOQ_hresult("com", "piiuiiii", "Proxy", pProxy, "AuthnSvc", dwAuthnSvc, "AuthzSvc", dwAuthzSvc, "ServerPrincName", pServerPrincName, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "AuthInfo", pAuthInfo, "Capabilities", dwCapabilities);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
HOOKDEF(void, WINAPI, CoUninitialize, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_CoUninitialize();
	LOQ_void("com", "");
}

// -> hook_com.c に追加 | category="com" | winapi:National Language Support (NLS)
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpVersionInformation: 型 LPNLSVERSIONINFO は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpReserved: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
// REVIEW: 引数 lParam: 型 LPARAM は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(int, WINAPI, CompareStringEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPCWSTR lpLocaleName,
	_In_ DWORD dwCmpFlags,
	_In_ LPCWSTR lpString1,
	_In_ int cchCount1,
	_In_ LPCWSTR lpString2,
	_In_ int cchCount2,
	_In_opt_ LPNLSVERSIONINFO lpVersionInformation,
	_In_opt_ LPVOID lpReserved,
	_In_opt_ LPARAM lParam
) {
	int ret;
	ret = Old_CompareStringEx(lpLocaleName, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2, lpVersionInformation, lpReserved, lParam);
	LOQ_nonzero("com", "uiuiuippp", "LocaleName", lpLocaleName, "CmpFlags", dwCmpFlags, "String1", lpString1, "Count1", cchCount1, "String2", lpString2, "Count2", cchCount2, "VersionInformation", lpVersionInformation, "Reserved", lpReserved, "LParam", lParam);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:National Language Support (NLS)
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 Locale: 型 LCID を i(int32)で仮記録。要確認
HOOKDEF(int, WINAPI, CompareStringW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LCID Locale,
	_In_ DWORD dwCmpFlags,
	_In_ LPCWSTR lpString1,
	_In_ int cchCount1,
	_In_ LPCWSTR lpString2,
	_In_ int cchCount2
) {
	int ret;
	ret = Old_CompareStringW(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
	LOQ_nonzero("com", "iiuiui", "Locale", Locale, "CmpFlags", dwCmpFlags, "String1", lpString1, "Count1", cchCount1, "String2", lpString2, "Count2", cchCount2);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Consoles
HOOKDEF(BOOL, WINAPI, GetConsoleMode, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hConsoleHandle,
	_Out_ LPDWORD lpMode
) {
	BOOL ret;
	ret = Old_GetConsoleMode(hConsoleHandle, lpMode);
	LOQ_bool("com", "pI", "ConsoleHandle", hConsoleHandle, "Mode", lpMode);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Consoles
// REVIEW: 戻り型 UINT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(UINT, WINAPI, GetConsoleOutputCP, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	UINT ret;
	ret = Old_GetConsoleOutputCP();
	LOQ_nonzero("com", "");
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Consoles
HOOKDEF(HANDLE, WINAPI, GetStdHandle, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD nStdHandle
) {
	HANDLE ret;
	ret = Old_GetStdHandle(nStdHandle);
	LOQ_handle("com", "i", "StdHandle", nStdHandle);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Consoles
// REVIEW: 引数 lpBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
// REVIEW: 引数 pInputControl: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(BOOL, WINAPI, ReadConsoleW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hConsoleInput,
	_Out_ LPVOID lpBuffer,
	_In_ DWORD nNumberOfCharsToRead,
	_Out_ LPDWORD lpNumberOfCharsRead,
	_In_opt_ LPVOID pInputControl
) {
	BOOL ret;
	ret = Old_ReadConsoleW(hConsoleInput, lpBuffer, nNumberOfCharsToRead, lpNumberOfCharsRead, pInputControl);
	LOQ_bool("com", "ppiIp", "ConsoleInput", hConsoleInput, "Buffer", lpBuffer, "NumberOfCharsToRead", nNumberOfCharsToRead, "NumberOfCharsRead", lpNumberOfCharsRead, "InputControl", pInputControl);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Consoles
HOOKDEF(BOOL, WINAPI, SetStdHandle, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD nStdHandle,
	_In_ HANDLE hHandle
) {
	BOOL ret;
	ret = Old_SetStdHandle(nStdHandle, hHandle);
	LOQ_bool("com", "ip", "StdHandle", nStdHandle, "Handle", hHandle);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Conversion and Manipulation
HOOKDEF(HRESULT, WINAPI, VariantClear, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ VARIANTARG* pvarg
) {
	HRESULT ret;
	ret = Old_VariantClear(pvarg);
	LOQ_hresult("com", "n", "Varg", pvarg);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Conversion and Manipulation
HOOKDEF(void, WINAPI, VariantInit, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Out_ VARIANTARG* pvarg
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_VariantInit(pvarg);
	LOQ_void("com", "n", "Varg", pvarg);
}
/* >>> AUTOHOOK_mitre_096_smbios_manufacturer_checker END <<< */

