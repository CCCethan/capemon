/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include "hooking.h"
#include "misc.h"
#include "pipe.h"
#include "log.h"

#define StringAtomSize 0x100

extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern void DumpSectionViewsForPid(DWORD Pid);

typedef DWORD (WINAPI * __GetWindowThreadProcessId)(
	__in HWND hWnd,
	__out_opt LPDWORD lpdwProcessId
);

__GetWindowThreadProcessId _GetWindowThreadProcessId;

DWORD WINAPI our_GetWindowThreadProcessId(
	__in HWND hWnd,
	__out_opt LPDWORD lpdwProcessId
) {
	lasterror_t lasterror;
	DWORD ret;

	get_lasterrors(&lasterror);
	if (!_GetWindowThreadProcessId) {
		_GetWindowThreadProcessId = (__GetWindowThreadProcessId)GetProcAddress(LoadLibraryA("user32"), "GetWindowThreadProcessId");
	}
	ret = _GetWindowThreadProcessId(hWnd, lpdwProcessId);
	set_lasterrors(&lasterror);
	return ret;
}

DWORD WINAPI GetThreadProcessId(
	__in DWORD ThreadId
) {
	lasterror_t lasterror;
	DWORD ret = 0;

	get_lasterrors(&lasterror);

	HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId);
	if (hThread) {
		ret = GetProcessIdOfThread(hThread);
		CloseHandle(hThread);
	}

	set_lasterrors(&lasterror);
	return ret;
}

typedef DWORD(WINAPI * __GetClassNameA)(
	_In_  HWND   hWnd,
	_Out_ LPTSTR lpClassName,
	_In_  int	nMaxCount
);

__GetClassNameA _GetClassNameA;

DWORD WINAPI our_GetClassNameA(
	_In_  HWND   hWnd,
	_Out_ LPSTR lpClassName,
	_In_  int	nMaxCount
) {
	lasterror_t lasterror;
	DWORD ret;

	get_lasterrors(&lasterror);
	if (!_GetClassNameA) {
		_GetClassNameA = (__GetClassNameA)GetProcAddress(LoadLibraryA("user32"), "GetClassNameA");
	}
	ret = _GetClassNameA(hWnd, lpClassName, nMaxCount);
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowA,
	__in_opt  LPCTSTR lpClassName,
	__in_opt  LPCTSTR lpWindowName
) {
	// The atom must be in the low-order word of lpClassName;
	// the high-order word must be zero (from MSDN documentation.)
	HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
	if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
		LOQ_nonnull("windows", "is", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowW,
	__in_opt  LPWSTR lpClassName,
	__in_opt  LPWSTR lpWindowName
) {
	HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
	if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
		LOQ_nonnull("windows", "iu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExA,
	__in_opt  HWND hwndParent,
	__in_opt  HWND hwndChildAfter,
	__in_opt  LPCTSTR lpszClass,
	__in_opt  LPCTSTR lpszWindow
) {
	HWND ret = Old_FindWindowExA(hwndParent, hwndChildAfter, lpszClass,
		lpszWindow);

	// lpszClass can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
		LOQ_nonnull("windows", "is", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExW,
	__in_opt  HWND hwndParent,
	__in_opt  HWND hwndChildAfter,
	__in_opt  LPWSTR lpszClass,
	__in_opt  LPWSTR lpszWindow
) {
	HWND ret = Old_FindWindowExW(hwndParent, hwndChildAfter, lpszClass,
		lpszWindow);
	// lpszClass can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
		LOQ_nonnull("windows", "iu", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, PostMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostThreadMessageA,
	_In_  DWORD idThread,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostThreadMessageA(idThread, Msg, wParam, lParam);

	DWORD pid = GetThreadProcessId(idThread);

	if (pid && pid != GetCurrentProcessId()) {
		DumpSectionViewsForPid(pid);
		ProcessMessage(pid, 0);
	}

	LOQ_bool("windows", "iii", "ProcessId", pid, "ThreadId", idThread, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostThreadMessageW,
	_In_  DWORD idThread,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostThreadMessageW(idThread, Msg, wParam, lParam);

	DWORD pid = GetThreadProcessId(idThread);

	if (pid && pid != GetCurrentProcessId()) {
		DumpSectionViewsForPid(pid);
		ProcessMessage(pid, 0);
	}

	LOQ_bool("windows", "iii", "ProcessId", pid, "ThreadId", idThread, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_SendMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	BOOL ret = Old_SendMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret;
	DWORD pid;
	lasterror_t lasterror;

	ret = Old_SendNotifyMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	get_lasterrors(&lasterror);
	if (hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			DumpSectionViewsForPid(pid);
			ProcessMessage(pid, 0);
		}
	}
	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	BOOL ret;
	DWORD pid;
	lasterror_t lasterror;

	ret = Old_SendNotifyMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	get_lasterrors(&lasterror);
	if (hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			DumpSectionViewsForPid(pid);
			ProcessMessage(pid, 0);
		}
	}
	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(LONG, WINAPI, SetWindowLongA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongA(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG_PTR ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongPtrA(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;
}

HOOKDEF(LONG, WINAPI, SetWindowLongW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongW(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;

}

HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG_PTR ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongPtrW(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;

}

HOOKDEF(BOOL, WINAPI, EnumWindows,
	_In_  WNDENUMPROC lpEnumFunc,
	_In_  LPARAM lParam
) {

	BOOL ret = Old_EnumWindows(lpEnumFunc, lParam);
	LOQ_bool("windows", "");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, CreateWindowExA,
	__in DWORD dwExStyle,
	__in_opt LPCSTR lpClassName,
	__in_opt LPCSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "isiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	else {
		LOQ_nonnull("windows", "ssiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}

	return 0;
}

HOOKDEF_NOTAIL(WINAPI, CreateWindowExW,
	__in DWORD dwExStyle,
	__in_opt LPWSTR lpClassName,
	__in_opt LPWSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "iuiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	else {
		LOQ_nonnull("windows", "uuiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	return 0;
}

HOOKDEF(int, WINAPI, MessageBoxTimeoutW,
	__in HWND hwndOwner,
	__in LPCWSTR lpszText,
	__in LPCWSTR lpszCaption,
	__in UINT wStyle,
	__in WORD wLanguageId,
	__in DWORD dwTimeout
) {
	int ret = Old_MessageBoxTimeoutW(hwndOwner, lpszText, lpszCaption, wStyle, wLanguageId, dwTimeout);
	if (dwTimeout == INFINITE)
		LOQ_zero("windows", "uus", "Text", lpszText, "Caption", lpszCaption, "Timeout", "Infinite");
	else
		LOQ_zero("windows", "uui", "Text", lpszText, "Caption", lpszCaption, "Timeout", dwTimeout);
	return ret;
}


/* ============================================================================
 * MIRAGE2 ADDED HOOKS -- hook_window.c
 * Auto-generated skeletons from data/api_hook_analysis/unhooked_api_classified.jsonl
 * Added 2026-07-11. Fill in spoofing/filtering logic per API as needed.
 * ============================================================================ */
HOOKDEF(BOOL, WINAPI, AddClipboardFormatListener,
	HWND hwnd
) {
	BOOL ret = Old_AddClipboardFormatListener(hwnd);
	LOQ_bool("window", "p", "Hwnd", hwnd);
	return ret;
}

HOOKDEF(BOOL, WINAPI, AttachThreadInput,
	DWORD idAttach,
	DWORD idAttachTo,
	BOOL fAttach
) {
	BOOL ret = Old_AttachThreadInput(idAttach, idAttachTo, fAttach);
	LOQ_bool("window", "iii", "IdAttach", idAttach, "IdAttachTo", idAttachTo, "FAttach", fAttach);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, CallNextHookEx,
	HHOOK hhk,
	int nCode,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret = Old_CallNextHookEx(hhk, nCode, wParam, lParam);
	LOQ_nonzero("window", "piip", "Hhk", hhk, "NCode", nCode, "WParam", wParam, "LParam", lParam);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ChangeClipboardChain,
	HWND hWndRemove,
	HWND hWndNewNext
) {
	BOOL ret = Old_ChangeClipboardChain(hWndRemove, hWndNewNext);
	LOQ_bool("window", "pp", "HWndRemove", hWndRemove, "HWndNewNext", hWndNewNext);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CloseClipboard
) {
	BOOL ret = Old_CloseClipboard();
	LOQ_bool("window", "");
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DefWindowProc,
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret = Old_DefWindowProc(hWnd, Msg, wParam, lParam);
	LOQ_nonzero("window", "piip", "HWnd", hWnd, "Msg", Msg, "WParam", wParam, "LParam", lParam);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DefWindowProcA,
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret = Old_DefWindowProcA(hWnd, Msg, wParam, lParam);
	LOQ_nonzero("window", "piip", "HWnd", hWnd, "Msg", Msg, "WParam", wParam, "LParam", lParam);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DefWindowProcW,
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret = Old_DefWindowProcW(hWnd, Msg, wParam, lParam);
	LOQ_nonzero("window", "piip", "HWnd", hWnd, "Msg", Msg, "WParam", wParam, "LParam", lParam);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DestroyWindow,
	HWND hWnd
) {
	BOOL ret = Old_DestroyWindow(hWnd);
	LOQ_bool("window", "p", "HWnd", hWnd);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DispatchMessage,
	const MSG* lpMsg
) {
	LRESULT ret = Old_DispatchMessage(lpMsg);
	LOQ_nonzero("window", "p", "LpMsg", lpMsg);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DispatchMessageA,
	const MSG* lpMsg
) {
	LRESULT ret = Old_DispatchMessageA(lpMsg);
	LOQ_nonzero("window", "p", "LpMsg", lpMsg);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DispatchMessageW,
	const MSG* lpMsg
) {
	LRESULT ret = Old_DispatchMessageW(lpMsg);
	LOQ_nonzero("window", "p", "LpMsg", lpMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EndDialog,
	HWND hDlg,
	INT_PTR nResult
) {
	BOOL ret = Old_EndDialog(hDlg, nResult);
	LOQ_bool("window", "pi", "HDlg", hDlg, "NResult", nResult);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplaySettings,
	LPCTSTR lpszDeviceName,
	DWORD iModeNum,
	DEVMODE* lpDevMode
) {
	BOOL ret = Old_EnumDisplaySettings(lpszDeviceName, iModeNum, lpDevMode);
	LOQ_bool("window", "sip", "LpszDeviceName", lpszDeviceName, "IModeNum", iModeNum, "LpDevMode", lpDevMode);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplaySettingsA,
	LPCSTR lpszDeviceName,
	DWORD iModeNum,
	DEVMODEA* lpDevMode
) {
	BOOL ret = Old_EnumDisplaySettingsA(lpszDeviceName, iModeNum, lpDevMode);
	LOQ_bool("window", "sip", "LpszDeviceName", lpszDeviceName, "IModeNum", iModeNum, "LpDevMode", lpDevMode);
	return ret;
}

HOOKDEF(DWORD, WINAPI, FormatMessageA,
	DWORD dwFlags,
	LPCVOID lpSource,
	DWORD dwMessageId,
	DWORD dwLanguageId,
	LPSTR lpBuffer,
	DWORD nSize,
	va_list* Arguments
) {
	DWORD ret = Old_FormatMessageA(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
	LOQ_nonzero("window", "ipiisip", "DwFlags", dwFlags, "LpSource", lpSource, "DwMessageId", dwMessageId, "DwLanguageId", dwLanguageId, "LpBuffer", lpBuffer, "NSize", nSize, "Arguments", Arguments);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetAncestor,
	HWND hwnd,
	UINT gaFlags
) {
	HWND ret = Old_GetAncestor(hwnd, gaFlags);
	LOQ_nonnull("window", "pi", "Hwnd", hwnd, "GaFlags", gaFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetClassInfoExA,
	HINSTANCE hInstance,
	LPCSTR lpszClass,
	LPWNDCLASSEXA lpwcx
) {
	BOOL ret = Old_GetClassInfoExA(hInstance, lpszClass, lpwcx);
	LOQ_bool("window", "psp", "HInstance", hInstance, "LpszClass", lpszClass, "Lpwcx", lpwcx);
	return ret;
}

HOOKDEF(int, WINAPI, GetClassName,
	HWND hWnd,
	LPTSTR lpClassName,
	int nMaxCount
) {
	int ret = Old_GetClassName(hWnd, lpClassName, nMaxCount);
	LOQ_nonzero("window", "psi", "HWnd", hWnd, "LpClassName", lpClassName, "NMaxCount", nMaxCount);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetClipboardOwner
) {
	HWND ret = Old_GetClipboardOwner();
	LOQ_nonnull("window", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetClipboardSequenceNumber
) {
	DWORD ret = Old_GetClipboardSequenceNumber();
	LOQ_nonzero("window", "");
	return ret;
}

HOOKDEF(HWND, WINAPI, GetConsoleWindow
) {
	HWND ret = Old_GetConsoleWindow();
	LOQ_nonnull("window", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetCursorInfo,
	PCURSORINFO pci
) {
	BOOL ret = Old_GetCursorInfo(pci);
	LOQ_bool("window", "p", "Pci", pci);
	return ret;
}

HOOKDEF(HDC, WINAPI, GetDC,
	HWND hWnd
) {
	HDC ret = Old_GetDC(hWnd);
	LOQ_nonnull("window", "p", "HWnd", hWnd);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetDesktopWindow
) {
	HWND ret = Old_GetDesktopWindow();
	LOQ_nonnull("window", "");
	return ret;
}

HOOKDEF(UINT, WINAPI, GetDoubleClickTime
) {
	UINT ret = Old_GetDoubleClickTime();
	LOQ_nonzero("window", "");
	return ret;
}

HOOKDEF(HWND, WINAPI, GetForegroundWindow
) {
	HWND ret = Old_GetForegroundWindow();
	LOQ_nonnull("window", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetGUIThreadInfo,
	DWORD idThread,
	PGUITHREADINFO pgui
) {
	BOOL ret = Old_GetGUIThreadInfo(idThread, pgui);
	LOQ_bool("window", "ip", "IdThread", idThread, "Pgui", pgui);
	return ret;
}

HOOKDEF(SHORT, WINAPI, GetKeyState,
	int nVirtKey
) {
	SHORT ret = Old_GetKeyState(nVirtKey);
	LOQ_nonzero("window", "i", "NVirtKey", nVirtKey);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetKeyboardLayoutNameA,
	LPSTR pwszKLID
) {
	BOOL ret = Old_GetKeyboardLayoutNameA(pwszKLID);
	LOQ_bool("window", "s", "PwszKLID", pwszKLID);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetKeyboardState,
	PBYTE lpKeyState
) {
	BOOL ret = Old_GetKeyboardState(lpKeyState);
	LOQ_bool("window", "p", "LpKeyState", lpKeyState);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMessage,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax
) {
	BOOL ret = Old_GetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	LOQ_bool("window", "ppii", "LpMsg", lpMsg, "HWnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMessageA,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax
) {
	BOOL ret = Old_GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	LOQ_bool("window", "ppii", "LpMsg", lpMsg, "HWnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMessageW,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax
) {
	BOOL ret = Old_GetMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	LOQ_bool("window", "ppii", "LpMsg", lpMsg, "HWnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMonitorInfo,
	HMONITOR hMonitor,
	LPMONITORINFO lpmi
) {
	BOOL ret = Old_GetMonitorInfo(hMonitor, lpmi);
	LOQ_bool("window", "pp", "HMonitor", hMonitor, "Lpmi", lpmi);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetRawInputBuffer,
	PRAWINPUT pData,
	PUINT pcbSize,
	UINT cbSizeHeader
) {
	UINT ret = Old_GetRawInputBuffer(pData, pcbSize, cbSizeHeader);
	LOQ_nonzero("window", "ppi", "PData", pData, "PcbSize", pcbSize, "CbSizeHeader", cbSizeHeader);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetRawInputData,
	HRAWINPUT hRawInput,
	UINT uiCommand,
	LPVOID pData,
	PUINT pcbSize,
	UINT cbSizeHeader
) {
	UINT ret = Old_GetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
	LOQ_nonzero("window", "pippi", "HRawInput", hRawInput, "UiCommand", uiCommand, "PData", pData, "PcbSize", pcbSize, "CbSizeHeader", cbSizeHeader);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetSystemWindowsDirectoryW,
	LPWSTR lpBuffer,
	UINT uSize
) {
	UINT ret = Old_GetSystemWindowsDirectoryW(lpBuffer, uSize);
	LOQ_nonzero("window", "ui", "LpBuffer", lpBuffer, "USize", uSize);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetWindow,
	HWND hWnd,
	UINT uCmd
) {
	HWND ret = Old_GetWindow(hWnd, uCmd);
	LOQ_nonnull("window", "pi", "HWnd", hWnd, "UCmd", uCmd);
	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, GetWindowLongPtr,
	HWND hWnd,
	int nIndex
) {
	LONG_PTR ret = Old_GetWindowLongPtr(hWnd, nIndex);
	LOQ_nonzero("window", "pi", "HWnd", hWnd, "NIndex", nIndex);
	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, GetWindowLongPtrA,
	HWND hWnd,
	int nIndex
) {
	LONG_PTR ret = Old_GetWindowLongPtrA(hWnd, nIndex);
	LOQ_nonzero("window", "pi", "HWnd", hWnd, "NIndex", nIndex);
	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, GetWindowLongPtrW,
	HWND hWnd,
	int nIndex
) {
	LONG_PTR ret = Old_GetWindowLongPtrW(hWnd, nIndex);
	LOQ_nonzero("window", "pi", "HWnd", hWnd, "NIndex", nIndex);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetWindowRect,
	HWND hWnd,
	LPRECT lpRect
) {
	BOOL ret = Old_GetWindowRect(hWnd, lpRect);
	LOQ_bool("window", "pp", "HWnd", hWnd, "LpRect", lpRect);
	return ret;
}

HOOKDEF(int, WINAPI, GetWindowText,
	HWND hWnd,
	LPTSTR lpString,
	int nMaxCount
) {
	int ret = Old_GetWindowText(hWnd, lpString, nMaxCount);
	LOQ_nonzero("window", "psi", "HWnd", hWnd, "LpString", lpString, "NMaxCount", nMaxCount);
	return ret;
}

HOOKDEF(int, WINAPI, GetWindowTextA,
	HWND hWnd,
	LPSTR lpString,
	int nMaxCount
) {
	int ret = Old_GetWindowTextA(hWnd, lpString, nMaxCount);
	LOQ_nonzero("window", "psi", "HWnd", hWnd, "LpString", lpString, "NMaxCount", nMaxCount);
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetWindowThreadProcessId,
	HWND hWnd,
	LPDWORD lpdwProcessId
) {
	DWORD ret = Old_GetWindowThreadProcessId(hWnd, lpdwProcessId);
	LOQ_nonzero("window", "pp", "HWnd", hWnd, "LpdwProcessId", lpdwProcessId);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetWindowsDirectoryA,
	LPSTR lpBuffer,
	UINT uSize
) {
	UINT ret = Old_GetWindowsDirectoryA(lpBuffer, uSize);
	LOQ_nonzero("window", "si", "LpBuffer", lpBuffer, "USize", uSize);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetWindowsDirectoryW,
	LPWSTR lpBuffer,
	UINT uSize
) {
	UINT ret = Old_GetWindowsDirectoryW(lpBuffer, uSize);
	LOQ_nonzero("window", "ui", "LpBuffer", lpBuffer, "USize", uSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, IsWindowVisible,
	HWND hWnd
) {
	BOOL ret = Old_IsWindowVisible(hWnd);
	LOQ_bool("window", "p", "HWnd", hWnd);
	return ret;
}

HOOKDEF(BOOL, WINAPI, KillTimer,
	HWND hWnd,
	UINT_PTR uIDEvent
) {
	BOOL ret = Old_KillTimer(hWnd, uIDEvent);
	LOQ_bool("window", "pi", "HWnd", hWnd, "UIDEvent", uIDEvent);
	return ret;
}

HOOKDEF(HCURSOR, WINAPI, LoadCursor,
	HINSTANCE hInstance,
	LPCTSTR lpCursorName
) {
	HCURSOR ret = Old_LoadCursor(hInstance, lpCursorName);
	LOQ_nonnull("window", "ps", "HInstance", hInstance, "LpCursorName", lpCursorName);
	return ret;
}

HOOKDEF(HCURSOR, WINAPI, LoadCursorW,
	HINSTANCE hInstance,
	LPCWSTR lpCursorName
) {
	HCURSOR ret = Old_LoadCursorW(hInstance, lpCursorName);
	LOQ_nonnull("window", "pu", "HInstance", hInstance, "LpCursorName", lpCursorName);
	return ret;
}

HOOKDEF(HICON, WINAPI, LoadIconW,
	HINSTANCE hInstance,
	LPCWSTR lpIconName
) {
	HICON ret = Old_LoadIconW(hInstance, lpIconName);
	LOQ_nonnull("window", "pu", "HInstance", hInstance, "LpIconName", lpIconName);
	return ret;
}

HOOKDEF(HMONITOR, WINAPI, MonitorFromWindow,
	HWND hwnd,
	DWORD dwFlags
) {
	HMONITOR ret = Old_MonitorFromWindow(hwnd, dwFlags);
	LOQ_nonnull("window", "pi", "Hwnd", hwnd, "DwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, OpenClipboard,
	HWND hWndNewOwner
) {
	BOOL ret = Old_OpenClipboard(hWndNewOwner);
	LOQ_bool("window", "p", "HWndNewOwner", hWndNewOwner);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessage,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax,
	UINT wRemoveMsg
) {
	BOOL ret = Old_PeekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("window", "ppiii", "LpMsg", lpMsg, "HWnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax, "WRemoveMsg", wRemoveMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessageA,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax,
	UINT wRemoveMsg
) {
	BOOL ret = Old_PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("window", "ppiii", "LpMsg", lpMsg, "HWnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax, "WRemoveMsg", wRemoveMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessageW,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax,
	UINT wRemoveMsg
) {
	BOOL ret = Old_PeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("window", "ppiii", "LpMsg", lpMsg, "HWnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax, "WRemoveMsg", wRemoveMsg);
	return ret;
}

HOOKDEF(void, WINAPI, PostQuitMessage,
	int nExitCode
) {
	int ret = 0;
	Old_PostQuitMessage(nExitCode);
	LOQ_void("window", "i", "NExitCode", nExitCode);
	return;
}

HOOKDEF(ATOM, WINAPI, RegisterClassA,
	const WNDCLASSA* lpWndClass
) {
	ATOM ret = Old_RegisterClassA(lpWndClass);
	LOQ_nonzero("window", "p", "LpWndClass", lpWndClass);
	return ret;
}

HOOKDEF(ATOM, WINAPI, RegisterClassExA,
	const WNDCLASSEXA* unnamedParam1
) {
	ATOM ret = Old_RegisterClassExA(unnamedParam1);
	LOQ_nonzero("window", "p", "UnnamedParam1", unnamedParam1);
	return ret;
}

HOOKDEF(ATOM, WINAPI, RegisterClassExW,
	const WNDCLASSEXW* unnamedParam1
) {
	ATOM ret = Old_RegisterClassExW(unnamedParam1);
	LOQ_nonzero("window", "p", "UnnamedParam1", unnamedParam1);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterHotKey,
	HWND hWnd,
	int id,
	UINT fsModifiers,
	UINT vk
) {
	BOOL ret = Old_RegisterHotKey(hWnd, id, fsModifiers, vk);
	LOQ_bool("window", "piii", "HWnd", hWnd, "Id", id, "FsModifiers", fsModifiers, "Vk", vk);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterRawInputDevices,
	PCRAWINPUTDEVICE pRawInputDevices,
	UINT uiNumDevices,
	UINT cbSize
) {
	BOOL ret = Old_RegisterRawInputDevices(pRawInputDevices, uiNumDevices, cbSize);
	LOQ_bool("window", "pii", "PRawInputDevices", pRawInputDevices, "UiNumDevices", uiNumDevices, "CbSize", cbSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterShellHookWindow,
	HWND hwnd
) {
	BOOL ret = Old_RegisterShellHookWindow(hwnd);
	LOQ_bool("window", "p", "Hwnd", hwnd);
	return ret;
}

HOOKDEF(UINT, WINAPI, RegisterWindowMessageA,
	LPCSTR lpString
) {
	UINT ret = Old_RegisterWindowMessageA(lpString);
	LOQ_nonzero("window", "s", "LpString", lpString);
	return ret;
}

HOOKDEF(int, WINAPI, ReleaseDC,
	HWND hWnd,
	HDC hDC
) {
	int ret = Old_ReleaseDC(hWnd, hDC);
	LOQ_nonzero("window", "pp", "HWnd", hWnd, "HDC", hDC);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveClipboardFormatListener,
	HWND hwnd
) {
	BOOL ret = Old_RemoveClipboardFormatListener(hwnd);
	LOQ_bool("window", "p", "Hwnd", hwnd);
	return ret;
}

HOOKDEF(HWND, WINAPI, SetClipboardViewer,
	HWND hWndNewViewer
) {
	HWND ret = Old_SetClipboardViewer(hWndNewViewer);
	LOQ_nonnull("window", "p", "HWndNewViewer", hWndNewViewer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetLayeredWindowAttributes,
	HWND hwnd,
	COLORREF crKey,
	BYTE bAlpha,
	DWORD dwFlags
) {
	BOOL ret = Old_SetLayeredWindowAttributes(hwnd, crKey, bAlpha, dwFlags);
	LOQ_bool("window", "piii", "Hwnd", hwnd, "CrKey", crKey, "BAlpha", bAlpha, "DwFlags", dwFlags);
	return ret;
}

HOOKDEF(UINT_PTR, WINAPI, SetTimer,
	HWND hWnd,
	UINT_PTR nIDEvent,
	UINT uElapse,
	TIMERPROC lpTimerFunc
) {
	UINT_PTR ret = Old_SetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc);
	LOQ_nonzero("window", "piii", "HWnd", hWnd, "NIDEvent", nIDEvent, "UElapse", uElapse, "LpTimerFunc", lpTimerFunc);
	return ret;
}

HOOKDEF(HWINEVENTHOOK, WINAPI, SetWinEventHook,
	DWORD eventMin,
	DWORD eventMax,
	HMODULE hmodWinEventProc,
	WINEVENTPROC pfnWinEventProc,
	DWORD idProcess,
	DWORD idThread,
	DWORD dwFlags
) {
	HWINEVENTHOOK ret = Old_SetWinEventHook(eventMin, eventMax, hmodWinEventProc, pfnWinEventProc, idProcess, idThread, dwFlags);
	LOQ_nonnull("window", "iipiiii", "EventMin", eventMin, "EventMax", eventMax, "HmodWinEventProc", hmodWinEventProc, "PfnWinEventProc", pfnWinEventProc, "IdProcess", idProcess, "IdThread", idThread, "DwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ShowWindow,
	HWND hWnd,
	int nCmdShow
) {
	BOOL ret = Old_ShowWindow(hWnd, nCmdShow);
	LOQ_bool("window", "pi", "HWnd", hWnd, "NCmdShow", nCmdShow);
	return ret;
}

HOOKDEF(BOOL, WINAPI, TranslateMessage,
	const MSG* lpMsg
) {
	BOOL ret = Old_TranslateMessage(lpMsg);
	LOQ_bool("window", "p", "LpMsg", lpMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWinEvent,
	HWINEVENTHOOK hWinEventHook
) {
	BOOL ret = Old_UnhookWinEvent(hWinEventHook);
	LOQ_bool("window", "p", "HWinEventHook", hWinEventHook);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterClassA,
	LPCSTR lpClassName,
	HINSTANCE hInstance
) {
	BOOL ret = Old_UnregisterClassA(lpClassName, hInstance);
	LOQ_bool("window", "sp", "LpClassName", lpClassName, "HInstance", hInstance);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterClassW,
	LPCWSTR lpClassName,
	HINSTANCE hInstance
) {
	BOOL ret = Old_UnregisterClassW(lpClassName, hInstance);
	LOQ_bool("window", "up", "LpClassName", lpClassName, "HInstance", hInstance);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UpdateWindow,
	HWND hWnd
) {
	BOOL ret = Old_UpdateWindow(hWnd);
	LOQ_bool("window", "p", "HWnd", hWnd);
	return ret;
}

HOOKDEF(HWND, WINAPI, WindowFromPoint,
	POINT Point
) {
	HWND ret = Old_WindowFromPoint(Point);
	LOQ_nonnull("window", "p", "Point", Point);
	return ret;
}
