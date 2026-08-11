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

/* >>> AUTOHOOK_galloro_181_vbox_acpi_registry_checker BEGIN <<< */
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
/* >>> AUTOHOOK_galloro_181_vbox_acpi_registry_checker END <<< */

