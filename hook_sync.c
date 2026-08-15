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
#include "log.h"


HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
	__out	   PHANDLE MutantHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		BOOLEAN InitialOwner
) {
	NTSTATUS ret = Old_NtCreateMutant(MutantHandle, DesiredAccess,
		ObjectAttributes, InitialOwner);
	LOQ_ntstatus("synchronization", "Poi", "Handle", MutantHandle,
		"MutexName", unistr_from_objattr(ObjectAttributes),
		"InitialOwner", InitialOwner);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
	__out	   PHANDLE MutantHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenMutant(MutantHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("synchronization", "Po", "Handle", MutantHandle,
		"MutexName", unistr_from_objattr(ObjectAttributes));
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReleaseMutant,
	__in		HANDLE MutantHandle,
	__out_opt   PLONG PreviousCount
) {
	NTSTATUS ret = Old_NtReleaseMutant(MutantHandle, PreviousCount);
	LOQ_ntstatus("synchronization", "h", "Handle", MutantHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		DWORD EventType,
	__in		BOOLEAN InitialState
) {
	NTSTATUS ret = Old_NtCreateEvent(EventHandle, DesiredAccess,
		ObjectAttributes, EventType, InitialState);
	UNICODE_STRING *eventname = unistr_from_objattr(ObjectAttributes);
	if (eventname && eventname->Length) {
		LOQ_ntstatus("synchronization", "Poii", "Handle", EventHandle,
			"EventName", eventname, "EventType", EventType, "InitialState", InitialState);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenEvent(EventHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("synchronization", "Po", "Handle", EventHandle,
		"EventName", unistr_from_objattr(ObjectAttributes));
	return ret;

}

HOOKDEF(NTSTATUS, WINAPI, NtCreateNamedPipeFile,
	OUT		PHANDLE NamedPipeFileHandle,
	IN		ACCESS_MASK DesiredAccess,
	IN		POBJECT_ATTRIBUTES ObjectAttributes,
	OUT		PIO_STATUS_BLOCK IoStatusBlock,
	IN		ULONG ShareAccess,
	IN		ULONG CreateDisposition,
	IN		ULONG CreateOptions,
	IN		ULONG NamedPipeType,
	IN		ULONG ReadMode,
	IN		ULONG CompletionMode,
	IN		ULONG MaxInstances,
	IN		ULONG InBufferSize,
	IN		ULONG OutBufferSize,
	IN		PLARGE_INTEGER DefaultTimeOut
) {
	NTSTATUS ret = Old_NtCreateNamedPipeFile(NamedPipeFileHandle,
		DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess,
		CreateDisposition, CreateOptions, NamedPipeType, ReadMode,
		CompletionMode, MaxInstances, InBufferSize, OutBufferSize,
		DefaultTimeOut);
	LOQ_ntstatus("synchronization", "PhOi", "NamedPipeHandle", NamedPipeFileHandle,
		"DesiredAccess", DesiredAccess, "PipeName", ObjectAttributes,
		"ShareAccess", ShareAccess);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAddAtom,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom
) {
	NTSTATUS ret = Old_NtAddAtom(AtomName, AtomNameLength, Atom);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteAtom,
	IN RTL_ATOM Atom
) {
	NTSTATUS ret = Old_NtDeleteAtom(Atom);
	LOQ_ntstatus("synchronization", "h", "Atom", Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtFindAtom,
	IN	PWCHAR AtomName,
	IN	ULONG AtomNameLength,
	OUT PRTL_ATOM Atom OPTIONAL
) {
	ENSURE_RTL_ATOM(Atom);
	NTSTATUS ret = Old_NtFindAtom(AtomName, AtomNameLength, Atom);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAddAtomEx,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom,
	IN	PVOID	Unknown
) {
	NTSTATUS ret = Old_NtAddAtomEx(AtomName, AtomNameLength, Atom, Unknown);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationAtom,
	IN	RTL_ATOM Atom,
	IN	ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN  ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	WCHAR* AtomName;
	ULONG AtomNameLength;
	
	NTSTATUS ret = Old_NtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
	
	if (NT_SUCCESS(ret) && AtomInformationClass == AtomBasicInformation)
	{
		AtomNameLength = (ULONG)((PATOM_BASIC_INFORMATION)AtomInformation)->NameLength;
		AtomName = ((PATOM_BASIC_INFORMATION)AtomInformation)->Name;
		LOQ_ntstatus("synchronization", "bih", "AtomName", AtomNameLength, AtomName, "Size", AtomNameLength, "Atom", Atom);
	}
	else
		LOQ_ntstatus("synchronization", "h", "Atom", Atom);
	
	return ret;
}

/* >>> AUTOHOOK_hookverify_uncovered BEGIN <<< */
// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(VOID, WINAPI, AcquireSRWLockExclusive, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ PSRWLOCK SRWLock
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_AcquireSRWLockExclusive(SRWLock);
	LOQ_void("sync", "P", "SRWLock", SRWLock);
}

// -> hook_sync.c に追加 | category="sync" | winapi:Event Logging
HOOKDEF(BOOL, WINAPI, CloseEventLog, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ HANDLE hEventLog
) {
	BOOL ret;
	ret = Old_CloseEventLog(hEventLog);
	LOQ_bool("sync", "p", "EventLog", hEventLog);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
// REVIEW: 引数 lpEventAttributes: 型 LPSECURITY_ATTRIBUTES は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HANDLE, WINAPI, CreateEventA, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
	_In_ BOOL bManualReset,
	_In_ BOOL bInitialState,
	_In_opt_ LPCSTR lpName
) {
	HANDLE ret;
	ret = Old_CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
	// [可読性7.5] EventAttributes は ② 固定サイズ構造体(LPSECURITY_ATTRIBUTES)。
	// 同ファイルの CreateFileW が既に sizeof(SECURITY_ATTRIBUTES) を長さに 'b' で記録しており
	// (ビルド実績あり=型は定義済み)、同一イディオムに揃える。_In_opt_ で NULL のことが多いが、
	// log.c の 'b' は NULL/例外を __try で保護し 0 バイト扱いにするため安全。
	LOQ_handle("sync", "biis", "EventAttributes", sizeof(SECURITY_ATTRIBUTES), lpEventAttributes, "ManualReset", bManualReset, "InitialState", bInitialState, "Name", lpName);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(void, WINAPI, DeleteCriticalSection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ LPCRITICAL_SECTION lpCriticalSection
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_DeleteCriticalSection(lpCriticalSection);
	LOQ_void("sync", "P", "CriticalSection", lpCriticalSection);
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(void, WINAPI, EnterCriticalSection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ LPCRITICAL_SECTION lpCriticalSection
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_EnterCriticalSection(lpCriticalSection);
	LOQ_void("sync", "P", "CriticalSection", lpCriticalSection);
}

// -> hook_sync.c に追加 | category="sync" | winapi:Event Logging
HOOKDEF(BOOL, WINAPI, GetNumberOfEventLogRecords, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hEventLog,
	_Out_ PDWORD NumberOfRecords
) {
	BOOL ret;
	ret = Old_GetNumberOfEventLogRecords(hEventLog, NumberOfRecords);
	LOQ_bool("sync", "pI", "EventLog", hEventLog, "NumberOfRecords", NumberOfRecords);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(BOOL, WINAPI, InitializeCriticalSectionAndSpinCount, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Out_ LPCRITICAL_SECTION lpCriticalSection,
	_In_ DWORD dwSpinCount
) {
	BOOL ret;
	ret = Old_InitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
	LOQ_bool("sync", "Pi", "CriticalSection", lpCriticalSection, "SpinCount", dwSpinCount);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(BOOL, WINAPI, InitializeCriticalSectionEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Out_ LPCRITICAL_SECTION lpCriticalSection,
	_In_ DWORD dwSpinCount,
	_In_ DWORD Flags
) {
	BOOL ret;
	ret = Old_InitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, Flags);
	LOQ_bool("sync", "Pii", "CriticalSection", lpCriticalSection, "SpinCount", dwSpinCount, "Flags", Flags);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(void, WINAPI, LeaveCriticalSection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ LPCRITICAL_SECTION lpCriticalSection
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_LeaveCriticalSection(lpCriticalSection);
	LOQ_void("sync", "P", "CriticalSection", lpCriticalSection);
}

// -> hook_sync.c に追加 | category="sync" | winapi:Event Logging
HOOKDEF(HANDLE, WINAPI, OpenEventLogW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPCWSTR lpUNCServerName,
	_In_ LPCWSTR lpSourceName
) {
	HANDLE ret;
	ret = Old_OpenEventLogW(lpUNCServerName, lpSourceName);
	LOQ_handle("sync", "uu", "UNCServerName", lpUNCServerName, "SourceName", lpSourceName);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(VOID, WINAPI, ReleaseSRWLockExclusive, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ PSRWLOCK SRWLock
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_ReleaseSRWLockExclusive(SRWLock);
	LOQ_void("sync", "P", "SRWLock", SRWLock);
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(BOOL, WINAPI, SetEvent, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hEvent
) {
	BOOL ret;
	ret = Old_SetEvent(hEvent);
	LOQ_bool("sync", "p", "Event", hEvent);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Client
// REVIEW: 戻り型 HWINEVENTHOOK の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpfnWinEventProc: 型 WINEVENTPROC を i(int32)で仮記録。要確認
HOOKDEF(HWINEVENTHOOK, WINAPI, SetWinEventHook, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ UINT eventMin,
	_In_ UINT eventMax,
	_In_ HMODULE hmodWinEventProc,
	_In_ WINEVENTPROC lpfnWinEventProc,
	_In_ DWORD idProcess,
	_In_ DWORD idThread,
	_In_ UINT dwflags
) {
	HWINEVENTHOOK ret;
	ret = Old_SetWinEventHook(eventMin, eventMax, hmodWinEventProc, lpfnWinEventProc, idProcess, idThread, dwflags);
	LOQ_nonzero("sync", "iipiiii", "EventMin", eventMin, "EventMax", eventMax, "ModWinEventProc", hmodWinEventProc, "FnWinEventProc", lpfnWinEventProc, "IdProcess", idProcess, "IdThread", idThread, "Flags", dwflags);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(BOOL, WINAPI, SleepConditionVariableSRW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ PCONDITION_VARIABLE ConditionVariable,
	_Inout_ PSRWLOCK SRWLock,
	_In_ DWORD dwMilliseconds,
	_In_ ULONG Flags
) {
	BOOL ret;
	ret = Old_SleepConditionVariableSRW(ConditionVariable, SRWLock, dwMilliseconds, Flags);
	LOQ_bool("sync", "PPii", "ConditionVariable", ConditionVariable, "SRWLock", SRWLock, "Milliseconds", dwMilliseconds, "Flags", Flags);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(BOOLEAN, WINAPI, TryAcquireSRWLockExclusive, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ PSRWLOCK SRWLock
) {
	BOOLEAN ret;
	ret = Old_TryAcquireSRWLockExclusive(SRWLock);
	LOQ_bool("sync", "P", "SRWLock", SRWLock);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Client
// REVIEW: 引数 hWinEventHook: 型 HWINEVENTHOOK は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(BOOL, WINAPI, UnhookWinEvent, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWINEVENTHOOK hWinEventHook
) {
	BOOL ret;
	ret = Old_UnhookWinEvent(hWinEventHook);
	LOQ_bool("sync", "p", "WinEventHook", hWinEventHook);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(DWORD, WINAPI, WaitForSingleObject, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
) {
	DWORD ret;
	ret = Old_WaitForSingleObject(hHandle, dwMilliseconds);
	LOQ_nonzero("sync", "pi", "Handle", hHandle, "Milliseconds", dwMilliseconds);
	return ret;
}

// -> hook_sync.c に追加 | category="sync" | winapi:Synchronization
HOOKDEF(VOID, WINAPI, WakeAllConditionVariable, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ PCONDITION_VARIABLE ConditionVariable
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_WakeAllConditionVariable(ConditionVariable);
	LOQ_void("sync", "P", "ConditionVariable", ConditionVariable);
}
/* >>> AUTOHOOK_hookverify_uncovered END <<< */

