
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

/* >>> AUTOHOOK_pa_alk_204_virtualbox_mac_checker BEGIN <<< */
// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pvReserved: 生バッファ(void*)。長さ引数とペアで S/b 指定を手動検討
HOOKDEF(HRESULT, WINAPI, CoInitializeEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPVOID pvReserved,
	_In_ DWORD dwCoInit
) {
	HRESULT ret;
	ret = Old_CoInitializeEx(pvReserved, dwCoInit);
	LOQ_hresult("com", "i", "CoInit", dwCoInit);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pSecDesc: 型 PSECURITY_DESCRIPTOR はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 asAuthSvc: 型 SOLE_AUTHENTICATION_SERVICE* はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pReserved1: 型 void* はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pAuthList: 型 void* はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pReserved3: 型 void* はログ指定子を自動決定できず(構造体等)。手動検討
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
	LOQ_hresult("com", "iiii", "CAuthSvc", cAuthSvc, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "Capabilities", dwCapabilities);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pProxy: 型 IUnknown* はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pServerPrincName: 型 OLECHAR* はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 引数 pAuthInfo: 型 RPC_AUTH_IDENTITY_HANDLE はログ指定子を自動決定できず(構造体等)。手動検討
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
	LOQ_hresult("com", "iiiii", "AuthnSvc", dwAuthnSvc, "AuthzSvc", dwAuthzSvc, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "Capabilities", dwCapabilities);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 記録できる引数を自動抽出できず(全て出力/バッファ/構造体)。手動でフォーマット記述が必要
HOOKDEF(void, WINAPI, CoUninitialize, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_CoUninitialize();
	LOQ_void("com", "");
}

// -> hook_com.c に追加 | category="com" | winapi:Conversion and Manipulation
// REVIEW: 引数 pvarg: 型 VARIANTARG* はログ指定子を自動決定できず(構造体等)。手動検討
// REVIEW: 記録できる引数を自動抽出できず(全て出力/バッファ/構造体)。手動でフォーマット記述が必要
HOOKDEF(HRESULT, WINAPI, VariantClear, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ VARIANTARG* pvarg
) {
	HRESULT ret;
	ret = Old_VariantClear(pvarg);
	LOQ_hresult("com", "");
	return ret;
}
/* >>> AUTOHOOK_pa_alk_204_virtualbox_mac_checker END <<< */

