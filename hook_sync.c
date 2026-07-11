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


/* ============================================================================
 * MIRAGE2 ADDED HOOKS -- hook_sync.c
 * Auto-generated skeletons from data/api_hook_analysis/unhooked_api_classified.jsonl
 * Added 2026-07-11. Fill in spoofing/filtering logic per API as needed.
 * ============================================================================ */
/* ---- MIRAGE2 REQUIRED TYPE HEADERS ---- */
#include <mmsystem.h>

#include <mmsystem.h>

HOOKDEF(BOOL, WINAPI, CancelWaitableTimer,
	HANDLE hTimer
) {
	BOOL ret = Old_CancelWaitableTimer(hTimer);
	LOQ_bool("sync", "p", "HTimer", hTimer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CloseEventLog,
	HANDLE hEventLog
) {
	BOOL ret = Old_CloseEventLog(hEventLog);
	LOQ_bool("sync", "p", "HEventLog", hEventLog);
	return ret;
}

HOOKDEF(void, WINAPI, CloseThreadpoolTimer,
	PTP_TIMER pti
) {
	int ret = 0;
	Old_CloseThreadpoolTimer(pti);
	LOQ_void("sync", "p", "Pti", pti);
	return;
}

HOOKDEF(void, WINAPI, CloseThreadpoolWait,
	PTP_WAIT pwa
) {
	int ret = 0;
	Old_CloseThreadpoolWait(pwa);
	LOQ_void("sync", "p", "Pwa", pwa);
	return;
}

HOOKDEF(HANDLE, WINAPI, CreateEvent,
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL bManualReset,
	BOOL bInitialState,
	LPCTSTR lpName
) {
	HANDLE ret = Old_CreateEvent(lpEventAttributes, bManualReset, bInitialState, lpName);
	LOQ_handle("sync", "piis", "LpEventAttributes", lpEventAttributes, "BManualReset", bManualReset, "BInitialState", bInitialState, "LpName", lpName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateEventA,
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL bManualReset,
	BOOL bInitialState,
	LPCSTR lpName
) {
	HANDLE ret = Old_CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
	LOQ_handle("sync", "piis", "LpEventAttributes", lpEventAttributes, "BManualReset", bManualReset, "BInitialState", bInitialState, "LpName", lpName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateIoCompletionPort,
	HANDLE FileHandle,
	HANDLE ExistingCompletionPort,
	ULONG_PTR CompletionKey,
	DWORD NumberOfConcurrentThreads
) {
	HANDLE ret = Old_CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
	LOQ_handle("sync", "ppii", "FileHandle", FileHandle, "ExistingCompletionPort", ExistingCompletionPort, "CompletionKey", CompletionKey, "NumberOfConcurrentThreads", NumberOfConcurrentThreads);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateSemaphoreA,
	LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
	LONG lInitialCount,
	LONG lMaximumCount,
	LPCSTR lpName
) {
	HANDLE ret = Old_CreateSemaphoreA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
	LOQ_handle("sync", "piis", "LpSemaphoreAttributes", lpSemaphoreAttributes, "LInitialCount", lInitialCount, "LMaximumCount", lMaximumCount, "LpName", lpName);
	return ret;
}

HOOKDEF(PTP_TIMER, WINAPI, CreateThreadpoolTimer,
	PTP_TIMER_CALLBACK pfnti,
	PVOID pv,
	PTP_CALLBACK_ENVIRON pcbe
) {
	PTP_TIMER ret = Old_CreateThreadpoolTimer(pfnti, pv, pcbe);
	LOQ_nonnull("sync", "ppp", "Pfnti", pfnti, "Pv", pv, "Pcbe", pcbe);
	return ret;
}

HOOKDEF(PTP_WAIT, WINAPI, CreateThreadpoolWait,
	PTP_WAIT_CALLBACK pfnwa,
	PVOID pv,
	PTP_CALLBACK_ENVIRON pcbe
) {
	PTP_WAIT ret = Old_CreateThreadpoolWait(pfnwa, pv, pcbe);
	LOQ_nonnull("sync", "ppp", "Pfnwa", pfnwa, "Pv", pv, "Pcbe", pcbe);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateTimerQueue
) {
	HANDLE ret = Old_CreateTimerQueue();
	LOQ_handle("sync", "");
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimer,
	LPSECURITY_ATTRIBUTES lpTimerAttributes,
	BOOL bManualReset,
	LPCTSTR lpTimerName
) {
	HANDLE ret = Old_CreateWaitableTimer(lpTimerAttributes, bManualReset, lpTimerName);
	LOQ_handle("sync", "pis", "LpTimerAttributes", lpTimerAttributes, "BManualReset", bManualReset, "LpTimerName", lpTimerName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimerA,
	LPSECURITY_ATTRIBUTES lpTimerAttributes,
	BOOL bManualReset,
	LPCSTR lpTimerName
) {
	HANDLE ret = Old_CreateWaitableTimerA(lpTimerAttributes, bManualReset, lpTimerName);
	LOQ_handle("sync", "pis", "LpTimerAttributes", lpTimerAttributes, "BManualReset", bManualReset, "LpTimerName", lpTimerName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimerExW,
	LPSECURITY_ATTRIBUTES lpTimerAttributes,
	LPCWSTR lpTimerName,
	DWORD dwFlags,
	DWORD dwDesiredAccess
) {
	HANDLE ret = Old_CreateWaitableTimerExW(lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess);
	LOQ_handle("sync", "puii", "LpTimerAttributes", lpTimerAttributes, "LpTimerName", lpTimerName, "DwFlags", dwFlags, "DwDesiredAccess", dwDesiredAccess);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimerW,
	LPSECURITY_ATTRIBUTES lpTimerAttributes,
	BOOL bManualReset,
	LPCWSTR lpTimerName
) {
	HANDLE ret = Old_CreateWaitableTimerW(lpTimerAttributes, bManualReset, lpTimerName);
	LOQ_handle("sync", "piu", "LpTimerAttributes", lpTimerAttributes, "BManualReset", bManualReset, "LpTimerName", lpTimerName);
	return ret;
}

HOOKDEF(void, WINAPI, DeleteCriticalSection,
	LPCRITICAL_SECTION lpCriticalSection
) {
	int ret = 0;
	Old_DeleteCriticalSection(lpCriticalSection);
	LOQ_void("sync", "p", "LpCriticalSection", lpCriticalSection);
	return;
}

HOOKDEF(BOOL, WINAPI, DeleteTimerQueue,
	HANDLE TimerQueue
) {
	BOOL ret = Old_DeleteTimerQueue(TimerQueue);
	LOQ_bool("sync", "p", "TimerQueue", TimerQueue);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteTimerQueueEx,
	HANDLE TimerQueue,
	HANDLE CompletionEvent
) {
	BOOL ret = Old_DeleteTimerQueueEx(TimerQueue, CompletionEvent);
	LOQ_bool("sync", "pp", "TimerQueue", TimerQueue, "CompletionEvent", CompletionEvent);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteTimerQueueTimer,
	HANDLE TimerQueue,
	HANDLE Timer,
	HANDLE CompletionEvent
) {
	BOOL ret = Old_DeleteTimerQueueTimer(TimerQueue, Timer, CompletionEvent);
	LOQ_bool("sync", "ppp", "TimerQueue", TimerQueue, "Timer", Timer, "CompletionEvent", CompletionEvent);
	return ret;
}

HOOKDEF(void, WINAPI, EnterCriticalSection,
	LPCRITICAL_SECTION lpCriticalSection
) {
	int ret = 0;
	Old_EnterCriticalSection(lpCriticalSection);
	LOQ_void("sync", "p", "LpCriticalSection", lpCriticalSection);
	return;
}

HOOKDEF(BOOL, WINAPI, GenerateConsoleCtrlEvent,
	DWORD dwCtrlEvent,
	DWORD dwProcessGroupId
) {
	BOOL ret = Old_GenerateConsoleCtrlEvent(dwCtrlEvent, dwProcessGroupId);
	LOQ_bool("sync", "ii", "DwCtrlEvent", dwCtrlEvent, "DwProcessGroupId", dwProcessGroupId);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetNumberOfConsoleInputEvents,
	HANDLE hConsoleInput,
	LPDWORD lpNumberOfEvents
) {
	BOOL ret = Old_GetNumberOfConsoleInputEvents(hConsoleInput, lpNumberOfEvents);
	LOQ_bool("sync", "pp", "HConsoleInput", hConsoleInput, "LpNumberOfEvents", lpNumberOfEvents);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetNumberOfEventLogRecords,
	HANDLE hEventLog,
	PDWORD NumberOfRecords
) {
	BOOL ret = Old_GetNumberOfEventLogRecords(hEventLog, NumberOfRecords);
	LOQ_bool("sync", "pp", "HEventLog", hEventLog, "NumberOfRecords", NumberOfRecords);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetOldestEventLogRecord,
	HANDLE hEventLog,
	PDWORD OldestRecord
) {
	BOOL ret = Old_GetOldestEventLogRecord(hEventLog, OldestRecord);
	LOQ_bool("sync", "pp", "HEventLog", hEventLog, "OldestRecord", OldestRecord);
	return ret;
}

HOOKDEF(void, WINAPI, InitializeConditionVariable,
	PCONDITION_VARIABLE ConditionVariable
) {
	int ret = 0;
	Old_InitializeConditionVariable(ConditionVariable);
	LOQ_void("sync", "p", "ConditionVariable", ConditionVariable);
	return;
}

HOOKDEF(void, WINAPI, InitializeCriticalSection,
	LPCRITICAL_SECTION lpCriticalSection
) {
	int ret = 0;
	Old_InitializeCriticalSection(lpCriticalSection);
	LOQ_void("sync", "p", "LpCriticalSection", lpCriticalSection);
	return;
}

HOOKDEF(void, WINAPI, LeaveCriticalSection,
	LPCRITICAL_SECTION lpCriticalSection
) {
	int ret = 0;
	Old_LeaveCriticalSection(lpCriticalSection);
	LOQ_void("sync", "p", "LpCriticalSection", lpCriticalSection);
	return;
}

HOOKDEF(DWORD, WINAPI, MsgWaitForMultipleObjects,
	DWORD nCount,
	const HANDLE* pHandles,
	BOOL fWaitAll,
	DWORD dwMilliseconds,
	DWORD dwWakeMask
) {
	DWORD ret = Old_MsgWaitForMultipleObjects(nCount, pHandles, fWaitAll, dwMilliseconds, dwWakeMask);
	LOQ_nonzero("sync", "ipiii", "NCount", nCount, "PHandles", pHandles, "FWaitAll", fWaitAll, "DwMilliseconds", dwMilliseconds, "DwWakeMask", dwWakeMask);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenEventLog,
	LPCTSTR lpUNCServerName,
	LPCTSTR lpSourceName
) {
	HANDLE ret = Old_OpenEventLog(lpUNCServerName, lpSourceName);
	LOQ_handle("sync", "ss", "LpUNCServerName", lpUNCServerName, "LpSourceName", lpSourceName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenEventLogA,
	LPCSTR lpUNCServerName,
	LPCSTR lpSourceName
) {
	HANDLE ret = Old_OpenEventLogA(lpUNCServerName, lpSourceName);
	LOQ_handle("sync", "ss", "LpUNCServerName", lpUNCServerName, "LpSourceName", lpSourceName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenEventLogW,
	LPCWSTR lpUNCServerName,
	LPCWSTR lpSourceName
) {
	HANDLE ret = Old_OpenEventLogW(lpUNCServerName, lpSourceName);
	LOQ_handle("sync", "uu", "LpUNCServerName", lpUNCServerName, "LpSourceName", lpSourceName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, QueueUserWorkItem,
	LPTHREAD_START_ROUTINE Function,
	PVOID Context,
	ULONG Flags
) {
	BOOL ret = Old_QueueUserWorkItem(Function, Context, Flags);
	LOQ_bool("sync", "ppi", "Function", Function, "Context", Context, "Flags", Flags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ReadEventLog,
	HANDLE hEventLog,
	DWORD dwReadFlags,
	DWORD dwRecordOffset,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	DWORD* pnBytesRead,
	DWORD* pnMinNumberOfBytesNeeded
) {
	BOOL ret = Old_ReadEventLog(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded);
	LOQ_bool("sync", "piipipp", "HEventLog", hEventLog, "DwReadFlags", dwReadFlags, "DwRecordOffset", dwRecordOffset, "LpBuffer", lpBuffer, "NNumberOfBytesToRead", nNumberOfBytesToRead, "PnBytesRead", pnBytesRead, "PnMinNumberOfBytesNeeded", pnMinNumberOfBytesNeeded);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterWaitForSingleObject,
	PHANDLE phNewWaitObject,
	HANDLE hObject,
	WAITORTIMERCALLBACK Callback,
	PVOID Context,
	ULONG dwMilliseconds,
	ULONG dwFlags
) {
	BOOL ret = Old_RegisterWaitForSingleObject(phNewWaitObject, hObject, Callback, Context, dwMilliseconds, dwFlags);
	LOQ_bool("sync", "ppipii", "PhNewWaitObject", phNewWaitObject, "HObject", hObject, "Callback", Callback, "Context", Context, "DwMilliseconds", dwMilliseconds, "DwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ReleaseSemaphore,
	HANDLE hSemaphore,
	LONG lReleaseCount,
	LPLONG lpPreviousCount
) {
	BOOL ret = Old_ReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount);
	LOQ_bool("sync", "pip", "HSemaphore", hSemaphore, "LReleaseCount", lReleaseCount, "LpPreviousCount", lpPreviousCount);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetEvent,
	HANDLE hEvent
) {
	BOOL ret = Old_SetEvent(hEvent);
	LOQ_bool("sync", "p", "HEvent", hEvent);
	return ret;
}

HOOKDEF(void, WINAPI, SetThreadpoolTimer,
	PTP_TIMER pti,
	PFILETIME pftDueTime,
	DWORD msPeriod,
	DWORD msWindowLength
) {
	int ret = 0;
	Old_SetThreadpoolTimer(pti, pftDueTime, msPeriod, msWindowLength);
	LOQ_void("sync", "ppii", "Pti", pti, "PftDueTime", pftDueTime, "MsPeriod", msPeriod, "MsWindowLength", msWindowLength);
	return;
}

HOOKDEF(void, WINAPI, SetThreadpoolWait,
	PTP_WAIT pwa,
	HANDLE h,
	PFILETIME pftTimeout
) {
	int ret = 0;
	Old_SetThreadpoolWait(pwa, h, pftTimeout);
	LOQ_void("sync", "ppp", "Pwa", pwa, "H", h, "PftTimeout", pftTimeout);
	return;
}

HOOKDEF(BOOL, WINAPI, SetWaitableTimer,
	HANDLE hTimer,
	const LARGE_INTEGER* lpDueTime,
	LONG lPeriod,
	PTIMERAPCROUTINE pfnCompletionRoutine,
	LPVOID lpArgToCompletionRoutine,
	BOOL fResume
) {
	BOOL ret = Old_SetWaitableTimer(hTimer, lpDueTime, lPeriod, pfnCompletionRoutine, lpArgToCompletionRoutine, fResume);
	LOQ_bool("sync", "ppippi", "HTimer", hTimer, "LpDueTime", lpDueTime, "LPeriod", lPeriod, "PfnCompletionRoutine", pfnCompletionRoutine, "LpArgToCompletionRoutine", lpArgToCompletionRoutine, "FResume", fResume);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SleepConditionVariableCS,
	PCONDITION_VARIABLE ConditionVariable,
	PCRITICAL_SECTION CriticalSection,
	DWORD dwMilliseconds
) {
	BOOL ret = Old_SleepConditionVariableCS(ConditionVariable, CriticalSection, dwMilliseconds);
	LOQ_bool("sync", "ppi", "ConditionVariable", ConditionVariable, "CriticalSection", CriticalSection, "DwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterWait,
	HANDLE WaitHandle
) {
	BOOL ret = Old_UnregisterWait(WaitHandle);
	LOQ_bool("sync", "p", "WaitHandle", WaitHandle);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterWaitEx,
	HANDLE WaitHandle,
	HANDLE CompletionEvent
) {
	BOOL ret = Old_UnregisterWaitEx(WaitHandle, CompletionEvent);
	LOQ_bool("sync", "pp", "WaitHandle", WaitHandle, "CompletionEvent", CompletionEvent);
	return ret;
}

HOOKDEF(DWORD, WINAPI, WaitForMultipleObjects,
	DWORD nCount,
	const HANDLE* lpHandles,
	BOOL bWaitAll,
	DWORD dwMilliseconds
) {
	DWORD ret = Old_WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
	LOQ_nonzero("sync", "ipii", "NCount", nCount, "LpHandles", lpHandles, "BWaitAll", bWaitAll, "DwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(DWORD, WINAPI, WaitForMultipleObjectsEx,
	DWORD nCount,
	const HANDLE* lpHandles,
	BOOL bWaitAll,
	DWORD dwMilliseconds,
	BOOL bAlertable
) {
	DWORD ret = Old_WaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, bAlertable);
	LOQ_nonzero("sync", "ipiii", "NCount", nCount, "LpHandles", lpHandles, "BWaitAll", bWaitAll, "DwMilliseconds", dwMilliseconds, "BAlertable", bAlertable);
	return ret;
}

HOOKDEF(DWORD, WINAPI, WaitForSingleObject,
	HANDLE hHandle,
	DWORD dwMilliseconds
) {
	DWORD ret = Old_WaitForSingleObject(hHandle, dwMilliseconds);
	LOQ_nonzero("sync", "pi", "HHandle", hHandle, "DwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(void, WINAPI, WaitForThreadpoolTimerCallbacks,
	PTP_TIMER pti,
	BOOL fCancelPendingCallbacks
) {
	int ret = 0;
	Old_WaitForThreadpoolTimerCallbacks(pti, fCancelPendingCallbacks);
	LOQ_void("sync", "pi", "Pti", pti, "FCancelPendingCallbacks", fCancelPendingCallbacks);
	return;
}

HOOKDEF(BOOL, WINAPI, WaitOnAddress,
	volatile VOID* Address,
	PVOID CompareAddress,
	SIZE_T AddressSize,
	DWORD dwMilliseconds
) {
	BOOL ret = Old_WaitOnAddress(Address, CompareAddress, AddressSize, dwMilliseconds);
	LOQ_bool("sync", "ppii", "Address", Address, "CompareAddress", CompareAddress, "AddressSize", AddressSize, "DwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(MMRESULT, WINAPI, timeKillEvent,
	UINT uTimerID
) {
	MMRESULT ret = Old_timeKillEvent(uTimerID);
	LOQ_nonzero("sync", "i", "UTimerID", uTimerID);
	return ret;
}
