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
#include "pipe.h"
#include "misc.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"
#include "ignore.h"
#include "powerbase.h"
#include "CAPE\CAPE.h"
#include "CAPE\Injection.h"
#include "CAPE\Debugger.h"
#include "CAPE\YaraHarness.h"

#define STATUS_BAD_COMPRESSION_BUFFER ((NTSTATUS)0xC0000242L)

extern char *our_process_name;
extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern const char* GetLanguageName(LANGID langID);

extern BOOL TraceRunning;

extern BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo);

LPTOP_LEVEL_EXCEPTION_FILTER TopLevelExceptionFilter;
DWORD ExportAddress;

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
	__in  int idHook,
	__in  HOOKPROC lpfn,
	__in  HINSTANCE hMod,
	__in  DWORD dwThreadId
) {

	HHOOK ret;

	if (hMod && lpfn && dwThreadId) {
		DWORD pid = get_pid_by_tid(dwThreadId);
		if (pid != GetCurrentProcessId())
			ProcessMessage(pid, 0);
	}

	ret = Old_SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hMod, "ThreadId", dwThreadId);
	return ret;
}

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
	__in  int idHook,
	__in  HOOKPROC lpfn,
	__in  HINSTANCE hMod,
	__in  DWORD dwThreadId
) {

	HHOOK ret;

	if (hMod && lpfn && dwThreadId) {
		DWORD pid = get_pid_by_tid(dwThreadId);
		if (pid != GetCurrentProcessId())
			ProcessMessage(pid, 0);
	}

	ret = Old_SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hMod, "ThreadId", dwThreadId);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
	__in  HHOOK hhk
) {

	BOOL ret = Old_UnhookWindowsHookEx(hhk);
	LOQ_bool("hooking", "p", "HookHandle", hhk);
	return ret;
}

HOOKDEF(LPTOP_LEVEL_EXCEPTION_FILTER, WINAPI, SetUnhandledExceptionFilter,
	_In_  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
) {
	BOOL ret = 1;
	LPTOP_LEVEL_EXCEPTION_FILTER res;

	if (g_config.debug)
		res = NULL;
	else {
		res = Old_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
		TopLevelExceptionFilter = lpTopLevelExceptionFilter;
	}

	LOQ_bool("hooking", "p", "ExceptionFilter", lpTopLevelExceptionFilter);
	return res;
}

#define ALLOW_UNHANDLED_EXCEPTIONS 1

HOOKDEF(LONG, WINAPI, UnhandledExceptionFilter,
	__in PEXCEPTION_POINTERS ExceptionInfo
) {
	LONG ret;
	if (ALLOW_UNHANDLED_EXCEPTIONS)
		ret = Old_UnhandledExceptionFilter(ExceptionInfo);
	else
		ret = EXCEPTION_EXECUTE_HANDLER;
	if (ExceptionInfo && !ExceptionInfo->ExceptionRecord->NumberParameters && (ExceptionInfo->ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
		LOQ_zero("process", "ppp", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags);
	else if (ExceptionInfo->ExceptionRecord->NumberParameters == 1 && (ExceptionInfo->ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
		LOQ_zero("process", "pppp", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "ExceptionInformation", ExceptionInfo->ExceptionRecord->ExceptionInformation[0]);
	else if (ExceptionInfo->ExceptionRecord->NumberParameters == 2 && (ExceptionInfo->ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
		LOQ_zero("process", "ppppp", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "ExceptionInformation[0]", ExceptionInfo->ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
	return ret;
}

PVECTORED_EXCEPTION_HANDLER SampleVectoredHandler;

LONG WINAPI New_VectoredExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	LONG ret = 0;
	if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size))
		return EXCEPTION_CONTINUE_SEARCH;
	else
	{
#ifdef _WIN64
		PVOID CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
		PVOID CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
		ret = SampleVectoredHandler(ExceptionInfo);
#ifdef _WIN64
		PVOID NewCIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
		PVOID NewCIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
		if (ret == EXCEPTION_CONTINUE_EXECUTION) {
			char disassembly[256] = {0};
			disassemble(CIP, disassembly, sizeof(disassembly));
			if (g_config.log_vexcept && NewCIP != CIP)
				LOQ_void("system", "pppipppps", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "NumberParameters", ExceptionInfo->ExceptionRecord->NumberParameters, "ExceptionInformation[0]", ExceptionInfo->ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionInfo->ExceptionRecord->ExceptionInformation[1], "PreviousIP", CIP, "NewIP", NewCIP, "Instruction", disassembly);
			else if (g_config.log_vexcept)
				LOQ_void("system", "pppipps", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "NumberParameters", ExceptionInfo->ExceptionRecord->NumberParameters, "ExceptionInformation[0]", ExceptionInfo->ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionInfo->ExceptionRecord->ExceptionInformation, "Instruction", disassembly);
			if (TraceRunning)
				SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
		}
		return ret;
	}
}

HOOKDEF(PVOID, WINAPI, RtlAddVectoredExceptionHandler,
	__in	ULONG First,
	__out   PVECTORED_EXCEPTION_HANDLER Handler
) {
	PVOID ret = 0;

	if (!SampleVectoredHandler) {
		SampleVectoredHandler = Handler;
		ret = Old_RtlAddVectoredExceptionHandler(First, New_VectoredExceptionFilter);
	}
	else
		ret = Old_RtlAddVectoredExceptionHandler(First, Handler);

	LOQ_nonnull("hooking", "ip", "First", First, "Handler", Handler);

	return ret;
}

HOOKDEF(ULONG, WINAPI, RtlRemoveVectoredExceptionHandler,
	__in	PVOID Handle
) {
	ULONG ret = 0;

	ret = Old_RtlRemoveVectoredExceptionHandler(Handle);

	LOQ_bool("hooking", "p", "Handle", Handle);

	return ret;
}

HOOKDEF(UINT, WINAPI, SetErrorMode,
	_In_ UINT uMode
) {
	UINT ret = 0;

	if (!g_config.debug)
	ret = Old_SetErrorMode(uMode);

	//LOQ_void("system", "h", "Mode", uMode);
	disable_tail_call_optimization();
	return ret;
}

// Called with the loader lock held
HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
	__in_opt	PWORD pwPath,
	__in_opt	PVOID Unused,
	__in		PUNICODE_STRING ModuleFileName,
	__out	   PHANDLE pHModule
) {
	NTSTATUS ret = Old_LdrGetDllHandle(pwPath, Unused, ModuleFileName, pHModule);
	LOQ_ntstatus("system", "oP", "FileName", ModuleFileName, "ModuleHandle", pHModule);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandleEx,
    __in ULONG Flags,
    __in_opt PWSTR DllPath,
    __in PULONG DllCharacteristics,
    __in PUNICODE_STRING DllName,
    __out_opt PVOID *DllHandle
) {
	NTSTATUS ret = Old_LdrGetDllHandleEx(Flags, DllPath, DllCharacteristics, DllName, DllHandle);
	if (DllHandle)
		LOQ_ntstatus("system", "oP", "DllName", DllName, "DllHandle", DllHandle);
	else
		LOQ_ntstatus("system", "o", "DllName", DllName);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
	__in		HMODULE ModuleHandle,
	__in_opt	PANSI_STRING FunctionName,
	__in_opt	WORD Ordinal,
	__out	   PVOID *FunctionAddress
) {
	NTSTATUS ret = Old_LdrGetProcedureAddress(ModuleHandle, FunctionName, Ordinal, FunctionAddress);

	if (FunctionName != NULL && FunctionName->Length == 13 && FunctionName->Buffer != NULL &&
		(!strncmp(FunctionName->Buffer, "EncodePointer", 13) || !strncmp(FunctionName->Buffer, "DecodePointer", 13)))
		return ret;

	if (ExportAddress && Ordinal == 1 && path_is_system(our_process_path_w) && !_stricmp(our_process_name, "rundll32.exe")) {
		*FunctionAddress = (PVOID)((PBYTE)ModuleHandle + ExportAddress);
		DebugOutput("LdrGetProcedureAddress: Patched export address to 0x%p", *FunctionAddress);
		ret = 0;
	}

	LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
		"FunctionName", FunctionName != NULL ? FunctionName->Length : 0, FunctionName != NULL ? FunctionName->Buffer : NULL,
		"Ordinal", Ordinal, "FunctionAddress", FunctionAddress);

	if (hook_info()->main_caller_retaddr && g_config.first_process && FunctionName != NULL && (ret == 0xc000007a || ret == 0xc0000139) && FunctionName->Length == 7 &&
		!strncmp(FunctionName->Buffer, "DllMain", 7) && wcsicmp(our_process_path_w, g_config.file_of_interest)) {
		log_flush();
		ExitThread(0);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddressForCaller,
	__in		HMODULE ModuleHandle,
	__in_opt	PANSI_STRING FunctionName,
	__in_opt	WORD Ordinal,
	__out		PVOID *FunctionAddress,
	__in		BOOL bValue,
	__in		PVOID *CallbackAddress
) {
	NTSTATUS ret = Old_LdrGetProcedureAddressForCaller(ModuleHandle, FunctionName, Ordinal, FunctionAddress, bValue, CallbackAddress);

	if (FunctionName != NULL && FunctionName->Length == 13 && FunctionName->Buffer != NULL &&
		(!strncmp(FunctionName->Buffer, "EncodePointer", 13) || !strncmp(FunctionName->Buffer, "DecodePointer", 13)))
		return ret;

	if (ExportAddress && Ordinal == 1 && path_is_system(our_process_path_w) && !_stricmp(our_process_name, "rundll32.exe")) {
		*FunctionAddress = (PVOID)((PBYTE)ModuleHandle + ExportAddress);
		DebugOutput("LdrGetProcedureAddress: Patched export address to 0x%p", *FunctionAddress);
		ret = 0;
	}

	LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
		"FunctionName", FunctionName != NULL ? FunctionName->Length : 0, FunctionName != NULL ? FunctionName->Buffer : NULL,
		"Ordinal", Ordinal, "FunctionAddress", FunctionAddress);

	if (hook_info()->main_caller_retaddr && g_config.first_process && FunctionName != NULL && (ret == 0xc000007a || ret == 0xc0000139) && FunctionName->Length == 7 &&
		!strncmp(FunctionName->Buffer, "DllMain", 7) && wcsicmp(our_process_path_w, g_config.file_of_interest)) {
		log_flush();
		ExitThread(0);
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, DeviceIoControl,
	__in		 HANDLE hDevice,
	__in		 DWORD dwIoControlCode,
	__in_opt	 LPVOID lpInBuffer,
	__in		 DWORD nInBufferSize,
	__out_opt	LPVOID lpOutBuffer,
	__in		 DWORD nOutBufferSize,
	__out_opt	LPDWORD lpBytesReturned,
	__inout_opt  LPOVERLAPPED lpOverlapped
) {
	BOOL ret;
	ENSURE_DWORD(lpBytesReturned);

	ret = Old_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
		nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned,
		lpOverlapped);
	LOQ_bool("device", "phbb", "DeviceHandle", hDevice, "IoControlCode", dwIoControlCode,
		"InBuffer", nInBufferSize, lpInBuffer,
		"OutBuffer", *lpBytesReturned, lpOutBuffer);

	if (!g_config.no_stealth && ret && lpOutBuffer)
		perform_device_fakery(lpOutBuffer, *lpBytesReturned, dwIoControlCode);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtShutdownSystem,
	__in  UINT Action
) {
	DWORD ret = 0;
	LOQ_zero("system", "i", "Action", Action);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtSetSystemPowerState,
	__in  UINT SystemAction,
	__in  UINT MinSystemState,
	__in  UINT Flags
) {
	DWORD ret = 0;
	LOQ_zero("system", "iih", "SystemAction", SystemAction, "MinSystemState", MinSystemState, "Flags", Flags);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, ExitWindowsEx,
	__in  UINT uFlags,
	__in  DWORD dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "hi", "Flags", uFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwGracePeriod,
	_In_	 DWORD  dwShutdownFlags,
	_In_	 DWORD  dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuihh", "MachineName", lpMachineName, "Message", lpMessage, "GracePeriod", dwGracePeriod, "ShutdownFlags", dwShutdownFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwTimeout,
	_In_	 BOOL	bForceAppsClosed,
	_In_	 BOOL	bRebootAfterShutdown
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiii", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtRaiseHardError,
	IN NTSTATUS 	ErrorStatus,
	IN ULONG 	NumberOfParameters,
	IN ULONG 	UnicodeStringParameterMask,
	IN PULONG_PTR 	Parameters,
	IN ULONG 	ValidResponseOptions,
	OUT PULONG 	Response
) {
	DWORD ret = 0;
	LOQ_zero("system", "hi", "ErrorStatus", ErrorStatus, "ResponseOptions", ValidResponseOptions);

	if (ValidResponseOptions == OptionShutdownSystem)
		pipe("SHUTDOWN:");

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownExW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwTimeout,
	_In_	 BOOL	bForceAppsClosed,
	_In_	 BOOL	bRebootAfterShutdown,
	_In_	 DWORD	dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiiih", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

static int num_isdebuggerpresent;

HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
	void
) {

	BOOL ret = Old_IsDebuggerPresent();
	num_isdebuggerpresent++;
	if (num_isdebuggerpresent < 20)
		LOQ_bool("system", "");
	else if (num_isdebuggerpresent == 20)
		LOQ_bool("system", "s", "Status", "Log limit reached");
#ifndef _WIN64
	else if (num_isdebuggerpresent == 1000) {
		lasterror_t lasterror;

		get_lasterrors(&lasterror);
		__try {
			hook_info_t *hookinfo = hook_info();
			PUCHAR p = (PUCHAR)hookinfo->main_caller_retaddr - 6;
			if (p[0] == 0xff && p[1] == 0x15 && p[6] == 0x49) {
				DWORD oldprot;
				VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldprot);
				memcpy(p, "\x31\xc0\x31\xc9\x41\x90", 6);
				VirtualProtect(p, 6, oldprot, &oldprot);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		set_lasterrors(&lasterror);
	}
#endif

	return ret;
}

HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
	__in_opt  LPWSTR lpSystemName,
	__in	  LPWSTR lpName,
	__out	 PLUID lpLuid
) {

	BOOL ret = Old_LookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
	LOQ_bool("system", "uu", "SystemName", lpSystemName, "PrivilegeName", lpName);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtClose,
	__in	HANDLE Handle
) {
	NTSTATUS ret;
	if (Handle == g_log_handle) {
		ret = STATUS_INVALID_HANDLE;
		LOQ_ntstatus("system", "ps", "Handle", Handle, "Alert", "Tried to close Cuckoo's log handle");
		return ret;
	}
	ret = Old_NtClose(Handle);
	LOQ_ntstatus("system", "p", "Handle", Handle);
	if(NT_SUCCESS(ret)) {
		remove_file_from_log_tracking(Handle);
		DumpSectionViewsForHandle(Handle);
		file_close(Handle);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDuplicateObject,
	__in	   HANDLE SourceProcessHandle,
	__in	   HANDLE SourceHandle,
	__in_opt   HANDLE TargetProcessHandle,
	__out_opt  PHANDLE TargetHandle,
	__in	   ACCESS_MASK DesiredAccess,
	__in	   ULONG HandleAttributes,
	__in	   ULONG Options
	) {
	NTSTATUS ret = Old_NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
		TargetHandle, DesiredAccess, HandleAttributes, Options);
	if (TargetHandle)
		LOQ_ntstatus("system", "pppPh", "SourceProcessHandle", SourceProcessHandle, "SourceHandle", SourceHandle, "TargetProcessHandle", TargetProcessHandle, "TargetHandle", TargetHandle, "Options", Options);
	else
		LOQ_ntstatus("system", "pph", "SourceProcessHandle", SourceProcessHandle, "SourceHandle", SourceHandle, "Options", Options);

	if (NT_SUCCESS(ret)) {
		if (TargetProcessHandle == NtCurrentProcess() && TargetHandle) {
			handle_duplicate(SourceHandle, *TargetHandle);
			handle_duplicate(SourceHandle, *TargetHandle);
		}
		if (SourceProcessHandle == NtCurrentProcess() && (Options & DUPLICATE_CLOSE_SOURCE)) {
			remove_file_from_log_tracking(SourceHandle);
			file_close(SourceHandle);
		}
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SaferIdentifyLevel,
	_In_	   DWORD				  dwNumProperties,
	_In_opt_   PVOID				  pCodeProperties,
	_Out_	  PVOID				  pLevelHandle,
	_Reserved_ LPVOID				 lpReserved
) {
	BOOL ret;
	ret = Old_SaferIdentifyLevel(dwNumProperties, pCodeProperties, pLevelHandle, lpReserved);
	LOQ_bool("misc", "");
	return ret;
}


HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
	__in	 HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakeTemporaryObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
	__in	 HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakePermanentObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleA,
	_In_		HANDLE hConsoleOutput,
	_In_		const VOID *lpBuffer,
	_In_		DWORD nNumberOfCharsToWrite,
	_Out_	   LPDWORD lpNumberOfCharsWritten,
	_Reserved_  LPVOID lpReseverd
) {
	BOOL ret = Old_WriteConsoleA(hConsoleOutput, lpBuffer,
		nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
	LOQ_bool("system", "pS", "ConsoleHandle", hConsoleOutput,
		"Buffer", nNumberOfCharsToWrite, lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleW,
	_In_		HANDLE hConsoleOutput,
	_In_		const VOID *lpBuffer,
	_In_		DWORD nNumberOfCharsToWrite,
	_Out_	   LPDWORD lpNumberOfCharsWritten,
	_Reserved_  LPVOID lpReseverd
) {
	BOOL ret = Old_WriteConsoleW(hConsoleOutput, lpBuffer,
		nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
	LOQ_bool("system", "pU", "ConsoleHandle", hConsoleOutput,
		"Buffer", nNumberOfCharsToWrite, lpBuffer);
	return ret;
}

HOOKDEF(int, WINAPI, GetSystemMetrics,
	_In_  int nIndex
) {
	int ret = Old_GetSystemMetrics(nIndex);

	if (!g_config.no_stealth) {
		if (nIndex == SM_CXSCREEN || nIndex == SM_CXVIRTUALSCREEN)
			ret = 1920;
		else if (nIndex == SM_CYSCREEN || nIndex == SM_CYVIRTUALSCREEN)
			ret = 1080;
	}

	if (nIndex == SM_CXSCREEN || nIndex == SM_CXVIRTUALSCREEN || nIndex == SM_CYSCREEN ||
		nIndex == SM_CYVIRTUALSCREEN || nIndex == SM_REMOTECONTROL || nIndex == SM_REMOTESESSION ||
		nIndex == SM_SHUTTINGDOWN || nIndex == SM_SWAPBUTTON)
		LOQ_nonzero("misc", "i", "SystemMetricIndex", nIndex);
	return ret;
}

typedef int (WINAPI * __GetSystemMetrics)(__in int nIndex);

__GetSystemMetrics _GetSystemMetrics;

DWORD WINAPI our_GetSystemMetrics(
	__in int nIndex
) {
	if (!_GetSystemMetrics) {
		_GetSystemMetrics = (__GetSystemMetrics)GetProcAddress(LoadLibraryA("user32"), "GetSystemMetrics");
	}
	return _GetSystemMetrics(nIndex);
}

static LARGE_INTEGER last_skipped;
static int num_to_spoof;
static int num_spoofed;
static int lastx;
static int lasty;

HOOKDEF(BOOL, WINAPI, GetCursorPos,
	_Out_ LPPOINT lpPoint
) {
	ENSURE_STRUCT(lpPoint, POINT);
	BOOL ret = Old_GetCursorPos(lpPoint);

	/* work around the fact that skipping sleeps prevents the human module from making the system look active */
	if (ret && time_skipped.QuadPart != last_skipped.QuadPart) {
		int xres, yres;
		xres = our_GetSystemMetrics(0);
		yres = our_GetSystemMetrics(1);
		if (!num_to_spoof)
			num_to_spoof = (random() % 20) + 10;
		if (num_spoofed < num_to_spoof) {
			lpPoint->x = random() % xres;
			lpPoint->y = random() % yres;
			num_spoofed++;
		}
		else {
			lpPoint->x = lastx;
			lpPoint->y = lasty;
			lastx = lpPoint->x;
			lasty = lpPoint->y;
		}
		last_skipped.QuadPart = time_skipped.QuadPart;
	}
	else if (last_skipped.QuadPart == 0) {
		last_skipped.QuadPart = time_skipped.QuadPart;
	}

	if (ret){
			LOQ_bool("misc", "ii", "x", lpPoint != NULL ? lpPoint->x : 0,
				 "y", lpPoint != NULL ? lpPoint->y : 0);
	}
	else{
		LOQ_bool("misc", "ii", "x", 0, "y", 0);
	}
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetLastError,
	void
)
{
	DWORD ret = Old_GetLastError();
	LOQ_void("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameA,
	_Out_	LPSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetComputerNameA(lpBuffer, lpnSize);
	LOQ_bool("misc", "s", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameW,
	_Out_	LPWSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetComputerNameW(lpBuffer, lpnSize);
	LOQ_bool("misc", "u", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameExW,
	__in	int NameType,
	__out	LPWSTR lpBuffer,
	__out	LPDWORD nSize
) {
	const wchar_t* ComputerNames[ComputerNameMax] = {
		L"NETBIOS",
		L"hostname",
		L"domain",
		L"fully.qualified.name",
		L"PHYSICAL-NETBIOS",
		L"physical-hostname",
		L"physical-domain",
		L"physical.fqdn"
	};
	DWORD bufsize = 0;
	if (nSize && *nSize)
		bufsize = *nSize;
	BOOL ret = Old_GetComputerNameExW(NameType, lpBuffer, nSize);
	if (ret && nSize && !*nSize && NameType < ComputerNameMax && wcslen(ComputerNames[NameType]) < bufsize) {
		bufsize = (DWORD)wcslen(ComputerNames[NameType]);
		wcsncpy(lpBuffer, ComputerNames[NameType], bufsize + 1);
		*nSize = bufsize;
	}
	LOQ_bool("misc", "u", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameA,
	_Out_	LPSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetUserNameA(lpBuffer, lpnSize);
	LOQ_bool("misc", "s", "Name", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameW,
	_Out_	LPWSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetUserNameW(lpBuffer, lpnSize);
	LOQ_bool("misc", "u", "Name", lpBuffer);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadDriver,
	__in PUNICODE_STRING DriverServiceName
) {
	NTSTATUS ret = Old_NtLoadDriver(DriverServiceName);
	LOQ_ntstatus("misc", "o", "DriverServiceName", DriverServiceName);
	return ret;
}

static unsigned int asynckeystate_logcount;

HOOKDEF(SHORT, WINAPI, GetAsyncKeyState,
	__in int vKey
) {
	SHORT ret = Old_GetAsyncKeyState(vKey);
	if (asynckeystate_logcount < 50 && ((vKey >= 0x30 && vKey <= 0x39) || (vKey >= 0x41 && vKey <= 0x5a))) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "i", "KeyCode", vKey);
	}
	else if (asynckeystate_logcount == 50) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "is", "KeyCode", vKey, "Status", "Log limit reached");
	}
	return ret;
}

#define PLUGX_SIGNATURE 0x5658	// 'XV'

HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

	LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		*FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", *FinalUncompressedSize);

	if ((NT_SUCCESS(ret) || ret == STATUS_BAD_COMPRESSION_BUFFER) && (*FinalUncompressedSize > 0)) {
		if (g_config.unpacker) {
			DebugOutput("RtlDecompressBuffer hook: scanning region 0x%p size 0x%x.\n", UncompressedBuffer, *FinalUncompressedSize);
			if (g_config.yarascan)
				YaraScan(UncompressedBuffer, *FinalUncompressedSize);
			CapeMetaData->DumpType = COMPRESSION;
			DumpPEsInRange(UncompressedBuffer, *FinalUncompressedSize);
			CapeMetaData->DumpType = UNPACKED_SHELLCODE;
			DumpMemory(UncompressedBuffer, *FinalUncompressedSize);
		}
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCompressBuffer,
	_In_  USHORT CompressionFormatAndEngine,
	_In_  PUCHAR UncompressedBuffer,
	_In_  ULONG  UncompressedBufferSize,
	_Out_ PUCHAR CompressedBuffer,
	_In_  ULONG  CompressedBufferSize,
	_In_  ULONG  UncompressedChunkSize,
	_Out_ PULONG FinalCompressedSize,
	_In_  PVOID  WorkSpace
) {
	NTSTATUS ret = Old_RtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace);

	LOQ_ntstatus("misc", "pbh", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		ret ? 0 : UncompressedBufferSize, UncompressedBuffer, "UncompressedBufferLength", ret ? 0 : UncompressedBufferSize);

	return ret;

}

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

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationProcess,
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
) {
	NTSTATUS ret = 0;
	if (!g_config.syscall || ProcessInformationClass != ProcessInstrumentationCallback)
		ret = Old_NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	if ((ProcessInformationClass == ProcessExecuteFlags || ProcessInformationClass == ProcessBreakOnTermination) && ProcessInformationLength == 4)
		LOQ_ntstatus("process", "ii", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", *(int*)ProcessInformation);
	else
		LOQ_ntstatus("process", "ib", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", ProcessInformationLength, ProcessInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationProcess,
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	NTSTATUS ret = Old_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	LOQ_ntstatus("process", "ib", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", ProcessInformationLength, ProcessInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemInformation,
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
) {
	NTSTATUS ret;
	char *buf;
	lasterror_t lasterror;
	ENSURE_ULONG(ReturnLength);

	if (SystemInformationClass != SystemProcessInformation || SystemInformation == NULL) {
normal_call:
		ret = Old_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

		if (!g_config.no_stealth && SystemInformationClass == SystemHypervisorDetailInformation) {
			if (SystemInformation && SystemInformationLength > 0) {
				memset(SystemInformation, 0, SystemInformationLength);
			}
			if (ReturnLength) {
				*ReturnLength = 0;
			}
			return 0xC0000003L; // STATUS_INVALID_INFO_CLASS
		}

		if (!g_config.no_stealth && SystemInformationClass == SystemBasicInformation && SystemInformationLength >= sizeof(SYSTEM_BASIC_INFORMATION) && NT_SUCCESS(ret)) {
			PSYSTEM_BASIC_INFORMATION p = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
			p->NumberOfProcessors = g_config.spoofed_cpu_count;
		}

		/* This is nearly arbitrary and simply designed to test whether the Upatre author(s) or others
		are reading this code */
		if (!g_config.no_stealth && SystemInformationClass == SystemProcessorPerformanceInformation &&
			NT_SUCCESS(ret) && SystemInformationLength >= (sizeof(LARGE_INTEGER) * 3)) {
			PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION perf_info = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)SystemInformation;
			perf_info->IdleTime.HighPart |= 2;
		}
		else if (!g_config.no_stealth && SystemInformationClass == SystemPerformanceInformation &&
			NT_SUCCESS(ret) && SystemInformationLength >= sizeof(LARGE_INTEGER)) {
			PLARGE_INTEGER perf_info = (PLARGE_INTEGER)SystemInformation;
			perf_info->HighPart |= 2;
		}

		return ret;
	}

	get_lasterrors(&lasterror);
	buf = calloc(1, SystemInformationLength);
	set_lasterrors(&lasterror);
	if (buf == NULL)
		goto normal_call;

	ret = Old_NtQuerySystemInformation(SystemInformationClass, buf, SystemInformationLength, ReturnLength);
	LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

	if (SystemInformationLength >= sizeof(SYSTEM_PROCESS_INFORMATION) && NT_SUCCESS(ret)) {
		PSYSTEM_PROCESS_INFORMATION our_p = (PSYSTEM_PROCESS_INFORMATION)buf;
		char *their_last_p = NULL;
		char *their_p = (char *)SystemInformation;
		ULONG lastlen = 0;
		while (1) {
			if (!is_protected_pid((DWORD)(ULONG_PTR)our_p->UniqueProcessId)) {
				PSYSTEM_PROCESS_INFORMATION tmp;
				if (our_p->NextEntryOffset)
					lastlen = our_p->NextEntryOffset;
				else
					lastlen = *ReturnLength - (ULONG)((char *)our_p - buf);
				// make sure we copy all data associated with the entry
				memcpy(their_p, our_p, lastlen);
				tmp = (PSYSTEM_PROCESS_INFORMATION)their_p;
				tmp->NextEntryOffset = lastlen;
				// adjust the only pointer field in the struct so that it points into the user's buffer,
				// but only if the pointer exists, otherwise we'd rewrite a NULL pointer to something not NULL
				if (tmp->ImageName.Buffer)
					tmp->ImageName.Buffer = (PWSTR)(((ULONG_PTR)tmp->ImageName.Buffer - (ULONG_PTR)our_p) + (ULONG_PTR)their_p);
				their_last_p = their_p;
				their_p += lastlen;
			}
			if (!our_p->NextEntryOffset)
				break;
			our_p = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)our_p + our_p->NextEntryOffset);
		}
		if (their_last_p) {
			PSYSTEM_PROCESS_INFORMATION tmp;
			tmp = (PSYSTEM_PROCESS_INFORMATION)their_last_p;
			*ReturnLength = (ULONG)(their_last_p + tmp->NextEntryOffset - (char *)SystemInformation);
			tmp->NextEntryOffset = 0;
		}
	}

	free(buf);

	return ret;
}

static GUID _CLSID_DiskDrive = { 0x4d36e967, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_CDROM = { 0x4d36e965, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_Display = { 0x4d36e968, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FDC = { 0x4d36e969, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_HDC = { 0x4d36e96a, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FloppyDisk = { 0x4d36e980, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };

static char *known_object(IID *cls)
{
	if (!memcmp(cls, &_CLSID_DiskDrive, sizeof(*cls)))
		return "DiskDrive";
	else if (!memcmp(cls, &_CLSID_CDROM, sizeof(*cls)))
		return "CDROM";
	else if (!memcmp(cls, &_CLSID_Display, sizeof(*cls)))
		return "Display";
	else if (!memcmp(cls, &_CLSID_FDC, sizeof(*cls)))
		return "FDC";
	else if (!memcmp(cls, &_CLSID_HDC, sizeof(*cls)))
		return "HDC";
	else if (!memcmp(cls, &_CLSID_FloppyDisk, sizeof(*cls)))
		return "FloppyDisk";

	return NULL;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsA,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_	   PCSTR Enumerator,
	_In_opt_	   HWND   hwndParent,
	_In_		   DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;
	HDEVINFO ret = Old_SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags);

	get_lasterrors(&lasterror);

	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		uuid_to_string(id1, idbuf);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);

		set_lasterrors(&lasterror);
	}
	return ret;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsW,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_	   PCWSTR Enumerator,
	_In_opt_	   HWND   hwndParent,
	_In_		   DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	HDEVINFO ret = Old_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		uuid_to_string(id1, idbuf);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);

		set_lasterrors(&lasterror);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyA,
	_In_	  HDEVINFO		 DeviceInfoSet,
	_In_	  PSP_DEVINFO_DATA DeviceInfoData,
	_In_	  DWORD			Property,
	_Out_opt_ PDWORD		   PropertyRegDataType,
	_Out_opt_ PBYTE			PropertyBuffer,
	_In_	  DWORD			PropertyBufferSize,
	_Out_opt_ PDWORD		   RequiredSize
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ENSURE_DWORD(RequiredSize);

	ret = Old_SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "VBOX", "DELL_");
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "QEMU", "DELL");
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "VMWARE", "DELL__");
	}

	if (PropertyBuffer)
		LOQ_bool("misc", "ir", "Property", Property, "PropertyBuffer", *PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	return ret;
}


HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyW,
	_In_	  HDEVINFO		 DeviceInfoSet,
	_In_	  PSP_DEVINFO_DATA DeviceInfoData,
	_In_	  DWORD			Property,
	_Out_opt_ PDWORD		   PropertyRegDataType,
	_Out_opt_ PBYTE			PropertyBuffer,
	_In_	  DWORD			PropertyBufferSize,
	_Out_opt_ PDWORD		   RequiredSize
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ENSURE_DWORD(RequiredSize);

	ret = Old_SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"VBOX", L"DELL_");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"QEMU", L"DELL");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"VMWARE", L"DELL__");
	}

	if (PropertyBuffer)
		LOQ_bool("misc", "iR", "Property", Property, "PropertyBuffer", *PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiBuildDriverInfoList,
	_In_	HDEVINFO		 DeviceInfoSet,
	_Inout_ PSP_DEVINFO_DATA DeviceInfoData,
	_In_	DWORD			DriverType
) {
	BOOL ret;
	ret = Old_SetupDiBuildDriverInfoList(DeviceInfoSet, DeviceInfoData, DriverType);
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImageEx,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink, // IUnknown *
	__in_opt LPCWSTR pszMIMETypeParam
) {
	HRESULT ret = Old_DecodeImageEx(pStream, pMap, pEventSink, pszMIMETypeParam);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImage,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink // IUnknown *
) {
	HRESULT ret = Old_DecodeImage(pStream, pMap, pEventSink);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LsaOpenPolicy,
	PLSA_UNICODE_STRING SystemName,
	PVOID ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PVOID PolicyHandle
) {
	NTSTATUS ret = Old_LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);
	LOQ_ntstatus("misc", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, WNetGetProviderNameW,
	__in DWORD dwNetType,
	__out LPWSTR lpProviderName,
	__inout LPDWORD lpBufferSize
) {
	DWORD ret;
	WCHAR *tmp = calloc(1, (*lpBufferSize + 1) * sizeof(wchar_t));

	if (tmp == NULL)
		return Old_WNetGetProviderNameW(dwNetType, lpProviderName, lpBufferSize);

	ret = Old_WNetGetProviderNameW(dwNetType, tmp, lpBufferSize);

	LOQ_zero("misc", "iu", "NetType", dwNetType, "ProviderName", ret == NO_ERROR ? tmp : L"");

	// WNNC_NET_RDR2SAMPLE, used for vbox detection
	if (!g_config.no_stealth && ret && dwNetType == 0x250000) {
		lasterror_t lasterrors;

		ret = ERROR_NO_NETWORK;
		lasterrors.Win32Error = ERROR_NO_NETWORK;
		lasterrors.NtstatusError = STATUS_ENTRYPOINT_NOT_FOUND;
		lasterrors.Eflags = 0;
	}
	else if (ret == NO_ERROR && lpProviderName) {
		wcscpy(lpProviderName, tmp);
	}

	free(tmp);

	return ret;
}

HOOKDEF(DWORD, WINAPI, RasValidateEntryNameW,
	_In_ LPCWSTR lpszPhonebook,
	_In_ LPCWSTR lpszEntry
) {
	DWORD ret = Old_RasValidateEntryNameW(lpszPhonebook, lpszEntry);
	LOQ_zero("misc", "uu", "Phonebook", lpszPhonebook, "Entry", lpszEntry);
	return ret;
}

HOOKDEF(DWORD, WINAPI, RasConnectionNotificationW,
	_In_ PVOID hrasconn,
	_In_ HANDLE   hEvent,
	_In_ DWORD	dwFlags
) {
	DWORD ret = Old_RasConnectionNotificationW(hrasconn, hEvent, dwFlags);
	LOQ_zero("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemTimeToTzSpecificLocalTime,
	_In_opt_ LPTIME_ZONE_INFORMATION lpTimeZone,
	_In_	 LPSYSTEMTIME			lpUniversalTime,
	_Out_	LPSYSTEMTIME			lpLocalTime
) {
	BOOL ret = Old_SystemTimeToTzSpecificLocalTime(lpTimeZone, lpUniversalTime, lpLocalTime);
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CLSIDFromProgID,
	_In_ LPCOLESTR lpszProgID,
	_Out_ LPCLSID lpclsid
) {
	HRESULT ret = Old_CLSIDFromProgID(lpszProgID, lpclsid);
	LOQ_hresult("misc", "u", "ProgID", lpszProgID);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CLSIDFromProgIDEx,
	_In_ LPCOLESTR lpszProgID,
	_Out_ LPCLSID lpclsid
) {
	HRESULT ret = Old_CLSIDFromProgIDEx(lpszProgID, lpclsid);
	LOQ_hresult("misc", "u", "ProgID", lpszProgID);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetCurrentHwProfileW,
	_Out_ LPHW_PROFILE_INFO lpHwProfileInfo
) {
	BOOL ret = Old_GetCurrentHwProfileW(lpHwProfileInfo);
	LOQ_bool("misc", "uu", "ProfileGUID", lpHwProfileInfo->szHwProfileGuid, "ProfileName", lpHwProfileInfo->szHwProfileName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, IsUserAdmin,
	void
) {
	BOOL ret = Old_IsUserAdmin();
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(void, WINAPI, GlobalMemoryStatus,
	_Out_ LPMEMORYSTATUS lpBuffer
) {
	BOOL ret = TRUE;
	Old_GlobalMemoryStatus(lpBuffer);
	if (!g_config.no_stealth && lpBuffer->dwTotalPhys < SPOOFED_RAM)
		lpBuffer->dwTotalPhys = (SIZE_T)SPOOFED_RAM;
	LOQ_void("misc", "ii", "MemoryLoad", lpBuffer->dwMemoryLoad, "TotalPhysicalMB", lpBuffer->dwTotalPhys / (1024 * 1024));
}

HOOKDEF(BOOL, WINAPI, GlobalMemoryStatusEx,
	_Out_ LPMEMORYSTATUSEX lpBuffer
) {
	BOOL ret = Old_GlobalMemoryStatusEx(lpBuffer);
	if (ret && !g_config.no_stealth && lpBuffer->ullTotalPhys < SPOOFED_RAM)
		lpBuffer->ullTotalPhys = SPOOFED_RAM;
	LOQ_void("misc", "ii", "MemoryLoad", lpBuffer->dwMemoryLoad, "TotalPhysicalMB", lpBuffer->ullTotalPhys / (1024 * 1024));
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetPhysicallyInstalledSystemMemory,
	_Out_ PULONGLONG TotalMemoryInKilobytes
) {
	BOOL ret = Old_GetPhysicallyInstalledSystemMemory(TotalMemoryInKilobytes);
	if (ret && !g_config.no_stealth && (*TotalMemoryInKilobytes * 1024) < SPOOFED_RAM)
		*TotalMemoryInKilobytes = SPOOFED_RAM / 1024;
	LOQ_void("misc", "i", "TotalMemoryInKilobytes", *TotalMemoryInKilobytes);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemParametersInfoA,
	_In_	UINT  uiAction,
	_In_	UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_	UINT  fWinIni
) {
	BOOL ret = Old_SystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
	if (ret && (uiAction == SPI_SETDESKWALLPAPER || uiAction == SPI_GETDESKWALLPAPER))
		LOQ_bool("misc", "hhs", "Action", uiAction, "uiParam", uiParam, "pvParam", pvParam);
	else
		LOQ_bool("misc", "hh", "Action", uiAction, "uiParam", uiParam);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemParametersInfoW,
	_In_	UINT  uiAction,
	_In_	UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_	UINT  fWinIni
) {
	BOOL ret = Old_SystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
	if (ret && (uiAction == SPI_SETDESKWALLPAPER || uiAction == SPI_GETDESKWALLPAPER))
		LOQ_bool("misc", "hhu", "Action", uiAction, "uiParam", uiParam, "pvParam", pvParam);
	else
		LOQ_bool("misc", "hh", "Action", uiAction, "uiParam", uiParam);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, PStoreCreateInstance,
	_Out_ PVOID **ppProvider,
	_In_  VOID *pProviderID,
	_In_  VOID *pReserved,
	_In_  DWORD dwFlags
) {
	HRESULT ret = Old_PStoreCreateInstance(ppProvider, pProviderID, pReserved, dwFlags);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(void, WINAPIV, srand,
	unsigned int seed
)
{
	int ret = 0;	// needed for LOQ_void

	Old_srand(seed);

	LOQ_void("misc", "h", "seed", seed);
}

HOOKDEF(LPSTR, WINAPI, lstrcpynA,
  _Out_ LPSTR   lpString1,
  _In_  LPSTR   lpString2,
  _In_  int	 iMaxLength
)
{
	LPSTR ret;

	ret = Old_lstrcpynA(lpString1, lpString2, iMaxLength);

	LOQ_nonzero("misc", "u", "String", lpString1);

	return ret;
}

HOOKDEF(int, WINAPI, lstrcmpiA,
  _In_  LPCSTR   lpString1,
  _In_  LPCSTR   lpString2
)
{
	int ret;

	ret = Old_lstrcmpiA(lpString1, lpString2);

	LOQ_nonzero("misc", "ss", "String1", lpString1, "String2", lpString2);

	return ret;
}

HOOKDEF(HRSRC, WINAPI, FindResourceExA,
	HMODULE hModule,
	LPCSTR lpType,
	LPCSTR lpName,
	WORD wLanguage
)
{
	HRSRC ret = Old_FindResourceExA(hModule, lpType, lpName, wLanguage);

	char type_id[8];
	if (IS_INTRESOURCE(lpType)) {
		snprintf(type_id, sizeof type_id, "#%hu", (WORD)lpType);
		lpType = type_id;
	}

	char name_id[8];
	if (IS_INTRESOURCE(lpName)) {
		snprintf(name_id, sizeof name_id, "#%hu", (WORD)lpName);
		lpName = name_id;
	}

	LOQ_handle("misc", "pssh", "Module", hModule, "Type", lpType, "Name", lpName, "Language", wLanguage);

	return ret;
}

HOOKDEF(HRSRC, WINAPI, FindResourceExW,
	HMODULE hModule,
	LPCWSTR lpType,
	LPCWSTR lpName,
	WORD wLanguage
)
{
	HRSRC ret = Old_FindResourceExW(hModule, lpType, lpName, wLanguage);

	wchar_t type_id[8];
	if (IS_INTRESOURCE(lpType)) {
		swprintf_s(type_id, sizeof(type_id), L"#%hu", (WORD)lpType);
		lpType = type_id;
	}

	wchar_t name_id[8];
	if (IS_INTRESOURCE(lpName)) {
		swprintf_s(name_id, sizeof(name_id), L"#%hu", (WORD)lpName);
		lpName = name_id;
	}

	LOQ_handle("misc", "puuh", "Module", hModule, "Type", lpType, "Name", lpName, "Language", wLanguage);

	return ret;
}

HOOKDEF(HGLOBAL, WINAPI, LoadResource,
  _In_opt_ HMODULE hModule,
  _In_	 HRSRC   hResInfo
)
{
	HGLOBAL ret = Old_LoadResource(hModule, hResInfo);

	LOQ_handle("misc", "pp", "Module", hModule, "ResourceInfo", hResInfo);

	return ret;
}

HOOKDEF(LPVOID, WINAPI, LockResource,
  _In_ HGLOBAL hResData
)
{
	LPVOID ret = Old_LockResource(hResData);

	LOQ_nonnull("misc", "p", "ResourceData", hResData);

	return ret;
}

HOOKDEF(DWORD, WINAPI, SizeofResource,
	_In_opt_ HMODULE hModule,
	_In_	 HRSRC   hResInfo
)
{
	DWORD ret = Old_SizeofResource(hModule, hResInfo);

	LOQ_nonzero("misc", "pp", "ModuleHandle", hModule, "ResourceInfo", hResInfo);

	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumResourceTypesExA,
	_In_opt_ HMODULE		 hModule,
	_In_	 ENUMRESTYPEPROC lpEnumFunc,
	_In_	 LONG_PTR		lParam,
	_In_	 DWORD		   dwFlags,
	_In_	 LANGID		  LangId
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "ppphh",
		"ModuleHandle", hModule,
		"EnumFunc", lpEnumFunc,
		"Parameter", lParam,
		"Flags", dwFlags,
		"LangId", LangId
	);
	return Old_EnumResourceTypesExA(hModule, lpEnumFunc, lParam, dwFlags, LangId);;
}

HOOKDEF(BOOL, WINAPI, EnumResourceTypesExW,
	_In_opt_ HMODULE		 hModule,
	_In_	 ENUMRESTYPEPROC lpEnumFunc,
	_In_	 LONG_PTR		lParam,
	_In_	 DWORD		   dwFlags,
	_In_	 LANGID		  LangId
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "ppphh",
		"ModuleHandle", hModule,
		"EnumFunc", lpEnumFunc,
		"Parameter", lParam,
		"Flags", dwFlags,
		"LangId", LangId
	);
	return Old_EnumResourceTypesExW(hModule, lpEnumFunc, lParam, dwFlags, LangId);;
}

HOOKDEF(BOOL, WINAPI, EnumCalendarInfoA,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID			  Locale,
	CALID			 Calendar,
	CALTYPE		   CalType
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phhh",
		"CalInfoEnumProc", lpCalInfoEnumProc,
		"Locale", Locale,
		"Calendar", Calendar,
		"CalType", CalType
	);
	return Old_EnumCalendarInfoA(lpCalInfoEnumProc, Locale, Calendar, CalType);
}

HOOKDEF(BOOL, WINAPI, EnumCalendarInfoW,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID			  Locale,
	CALID			 Calendar,
	CALTYPE		   CalType
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phhh",
		"CalInfoEnumProc", lpCalInfoEnumProc,
		"Locale", Locale,
		"Calendar", Calendar,
		"CalType", CalType
	);
	return Old_EnumCalendarInfoW(lpCalInfoEnumProc, Locale, Calendar, CalType);
}

HOOKDEF(BOOL, WINAPI, EnumTimeFormatsA,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID			  Locale,
	DWORD			 dwFlags
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phh",
		"TimeFmtEnumProc", lpTimeFmtEnumProc,
		"Locale", Locale,
		"Flags", dwFlags
	);
	return Old_EnumTimeFormatsA(lpTimeFmtEnumProc, Locale, dwFlags);
}

HOOKDEF(BOOL, WINAPI, EnumTimeFormatsW,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID			  Locale,
	DWORD			 dwFlags
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phh",
		"TimeFmtEnumProc", lpTimeFmtEnumProc,
		"Locale", Locale,
		"Flags", dwFlags
	);
	return Old_EnumTimeFormatsW(lpTimeFmtEnumProc, Locale, dwFlags);
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateTransaction,
	PHANDLE			TransactionHandle,
	ACCESS_MASK		DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID			 Uow,
	HANDLE			 TmHandle,
	ULONG			  CreateOptions,
	ULONG			  IsolationLevel,
	ULONG			  IsolationFlags,
	PLARGE_INTEGER	 Timeout,
	PUNICODE_STRING	Description
) {
	NTSTATUS ret = Old_NtCreateTransaction(TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
	LOQ_ntstatus("misc", "PhObphhhio",
		"TransactionHandle", TransactionHandle,
		"DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes,
		"UnitOfWork", sizeof (GUID), Uow,
		"TmHandle", TmHandle,
		"CreateOptions", CreateOptions,
		"IsolationLevel", IsolationLevel,
		"IsolationFlags", IsolationFlags,
		"Timeout", Timeout,
		"Description", Description
	);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenTransaction,
	PHANDLE			TransactionHandle,
	ACCESS_MASK		DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID			 Uow,
	HANDLE			 TmHandle
) {
	NTSTATUS ret = Old_NtOpenTransaction(TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle);
	LOQ_ntstatus("misc", "PhObp",
		"TransactionHandle", TransactionHandle,
		"DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes,
		"UnitOfWork", sizeof (GUID), Uow,
		"TmHandle", TmHandle
	);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtRollbackTransaction,
	HANDLE  TransactionHandle,
	BOOLEAN Wait
) {
	NTSTATUS ret = Old_NtRollbackTransaction(TransactionHandle, Wait);
	LOQ_ntstatus("misc", "pi", "TransactionHandle", TransactionHandle, "Wait", Wait);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCommitTransaction,
	HANDLE  TransactionHandle,
	BOOLEAN Wait
) {
	NTSTATUS ret = Old_NtCommitTransaction(TransactionHandle, Wait);
	LOQ_ntstatus("misc", "pi", "TransactionHandle", TransactionHandle, "Wait", Wait);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RtlSetCurrentTransaction,
	_In_ HANDLE	 TransactionHandle
) {
	BOOL ret = Old_RtlSetCurrentTransaction(TransactionHandle);
	LOQ_bool("misc", "p", "TransactionHandle", TransactionHandle);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, OleConvertOLESTREAMToIStorage,
	IN LPOLESTREAM		  lpolestream,
	OUT LPSTORAGE		   pstg,
	IN const DVTARGETDEVICE *ptd
) {
	void *buf = NULL; uintptr_t len = 0;

	HRESULT ret = Old_OleConvertOLESTREAMToIStorage(lpolestream, pstg, ptd);

#ifndef _WIN64
	if (lpolestream != NULL) {
		buf = (PVOID)*((uint8_t *) lpolestream + 8);
		len = *((uint8_t *) lpolestream + 12);
	}
#endif

	LOQ_bool("misc", "b", "OLE2", len, buf);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, HeapCreate,
  _In_ DWORD  flOptions,
  _In_ SIZE_T dwInitialSize,
  _In_ SIZE_T dwMaximumSize
)
{
	HANDLE ret;
	ret = Old_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
	LOQ_nonnull("misc", "ihh", "Options", flOptions, "InitialSize", dwInitialSize, "MaximumSize", dwMaximumSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsAlloc,
	_In_ PFLS_CALLBACK_FUNCTION lpCallback
) {
	BOOL ret = Old_FlsAlloc(lpCallback);
	LOQ_bool("misc", "p", "Callback", lpCallback);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsSetValue,
	_In_	 DWORD dwFlsIndex,
	_In_opt_ PVOID lpFlsData
) {
	BOOL ret = Old_FlsSetValue(dwFlsIndex, lpFlsData);
	LOQ_bool("misc", "ip", "Index", dwFlsIndex, "Data", lpFlsData);
	return ret;
}


HOOKDEF(PVOID, WINAPI, FlsGetValue,
	_In_	 DWORD dwFlsIndex
) {
	PVOID ret = Old_FlsGetValue(dwFlsIndex);
	LOQ_nonnull("misc", "ip", "Index", dwFlsIndex, "ReturnValue", ret);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsFree,
	_In_	 DWORD dwFlsIndex
) {
	BOOL ret = Old_FlsFree(dwFlsIndex);
	LOQ_bool("misc", "ip", "Index", dwFlsIndex);
	return ret;
}


HOOKDEF(PVOID, WINAPI, LocalAlloc,
	_In_ UINT uFlags,
	_In_ SIZE_T uBytes)
{
	PVOID ret = Old_LocalAlloc(uFlags, uBytes);
	LOQ_nonnull("misc", "ii", "Flags", uFlags, "Bytes", uBytes);
	return ret;
}

HOOKDEF(VOID, WINAPI, LocalFree,
	HLOCAL hMem)
{
	int ret = 0;
	Old_LocalFree(hMem);
	LOQ_void("misc", "p", "SourceBuffer", hMem);
}

#define MSGFLT_ADD 1
#define MSGFLT_REMOVE 2
HOOKDEF(BOOL, WINAPI, ChangeWindowMessageFilter,
	UINT  message,
	DWORD dwFlag
)
{
	BOOL ret;
	if (dwFlag != MSGFLT_REMOVE && dwFlag != MSGFLT_ADD) {
		ret = FALSE;
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	else
		ret = Old_ChangeWindowMessageFilter(message, dwFlag);
	LOQ_bool("misc", "ii", "message", message, "dwFlag", dwFlag);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, rtcEnvironBstr,
	struct envstruct *es
)
{
	LPWSTR ret = Old_rtcEnvironBstr(es);
	LOQ_bool("misc", "uu", "EnvVar", es->envstr, "EnvStr", ret);
	if (ret && !wcsicmp(es->envstr, L"userdomain"))
		// replace first char so it differs from computername
		*ret = '#';
	return ret;
}

HOOKDEF(HKL, WINAPI, GetKeyboardLayout,
	DWORD idThread
)
{
	HKL ret = Old_GetKeyboardLayout(idThread);
	if (g_config.lang)
		ret = (HKL)(DWORD_PTR)g_config.lang;
	const char* LanguageName = NULL;
	if (ret)
		LanguageName = GetLanguageName((LANGID)ret);
	if (LanguageName)
		LOQ_nonnull("misc", "ps", "KeyboardLayout", (DWORD_PTR)ret & 0xFFFF, "LanguageName", LanguageName);
	else
		LOQ_nonnull("misc", "p", "KeyboardLayout", (DWORD_PTR)ret & 0xFFFF);
	return ret;
}

HOOKDEF(VOID, WINAPI, RtlMoveMemory,
	_Out_	   VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_		SIZE_T		 Length
)
{
	int ret = 0;
	Old_RtlMoveMemory(Destination, Source, Length);
	LOQ_void("misc", "bppi", "Destination", Length, Destination, "Source", Source, "destination", Destination, "Length", Length);
	return;
}

HOOKDEF(void, WINAPI, OutputDebugStringA,
	LPCSTR lpOutputString
)
{
	int ret = 0;
	Old_OutputDebugStringA(lpOutputString);
	LOQ_void("misc", "s", "OutputString", lpOutputString);
	return;
}

HOOKDEF(void, WINAPI, OutputDebugStringW,
	LPCWSTR lpOutputString
)
{
	int ret = 0;
	Old_OutputDebugStringW(lpOutputString);
	LOQ_void("misc", "u", "OutputString", lpOutputString);
	return;
}

HOOKDEF(void, WINAPI, SysFreeString,
	BSTR bstrString
)
{
	int ret = 0;
	if (SysStringLen(bstrString) > 3)
		LOQ_void("misc", "u", "String", bstrString);
	Old_SysFreeString(bstrString);
	return;
}

HOOKDEF_NOTAIL(WINAPI, ScriptIsComplex,
	const WCHAR *pwcInChars,
	int cInChars,
	DWORD dwFlags
)
{
	DWORD ret = 0;
	if (cInChars > 1)
		LOQ_void("misc", "uii", "pwcInChars", pwcInChars, "cInChars", cInChars, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(int, WINAPI, StrCmpNICW,
	_In_ LPCWSTR pszStr1,
	_In_ LPCWSTR pszStr2,
	_In_ int nChar
)
{
	int ret;
	ret = Old_StrCmpNICW(pszStr1, pszStr2, nChar);
	LOQ_nonzero("misc", "uui", "String1", pszStr1, "String2", pszStr2, "nChar", nChar);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, VarBstrCat,
	_In_ BSTR bstrLeft,
	_In_ BSTR bstrRight,
	_In_ LPBSTR pbstrResult
)
{
	HRESULT ret = Old_VarBstrCat(bstrLeft, bstrRight, pbstrResult);
	LOQ_void("misc", "uuu", "bstrLeft", bstrLeft, "bstrRight", bstrRight, "pbstrResult", *pbstrResult);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, rtcCreateObject2,
	WORD *arg1,
	LPCOLESTR arg2,
	wchar_t arg3
)
{
	DWORD ret = 0;
	LOQ_void("misc", "u", "ProgID", arg2);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RtlDosPathNameToNtPathName_U,
	_In_	   PCWSTR DosFileName,
	_Out_	  PUNICODE_STRING NtFileName,
	_Out_opt_  PWSTR* FilePath,
	_Out_opt_  VOID* DirectoryInfo
)
{
	BOOL ret = Old_RtlDosPathNameToNtPathName_U(DosFileName, NtFileName, FilePath, DirectoryInfo);
	LOQ_bool("misc", "u", "DosFileName", DosFileName);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, DownloadFile,
	LPCSTR url,
	LPCSTR path,
	int flag
)
{
	DWORD ret = 0;
	LOQ_void("network", "ssi", "URL", url,"Path", path, "Flag",flag);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryLicenseValue,
	__in		PUNICODE_STRING Name,
	__in_opt	ULONG* Type,
	__in_opt	PVOID Buffer,
	__in		ULONG Length,
	__in		ULONG* DataLength
) {
	WCHAR VMDetection[] = L"Kernel-VMDetection-Private";
	NTSTATUS ret = Old_NtQueryLicenseValue(Name, Type, Buffer, Length, DataLength);
	if (NT_SUCCESS(ret) && Buffer && !wcsncmp(Name->Buffer, VMDetection, Name->Length))
		*(PBOOL)Buffer = FALSE;
	LOQ_ntstatus("system", "oP", "Name", Name, "Type", Type);
	return ret;
}

HOOKDEF(int, WINAPI, MultiByteToWideChar,
	__in		UINT	CodePage,
	__in		DWORD	dwFlags,
	__in		LPCCH	lpMultiByteStr,
	__in		int		cbMultiByte,
	__out_opt	LPWSTR	lpWideCharStr,
	__in		int		cchWideChar
) {
	DWORD ret = 0;
	if (CodePage == CP_ACP || CodePage == CP_UTF8)
		LOQ_zero("misc", "s", "String", lpMultiByteStr);
	return Old_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

HOOKDEF(int, WINAPI, WideCharToMultiByte,
	__in		UINT	CodePage,
	__in		DWORD	dwFlags,
	__in		LPCWCH	lpWideCharStr,
	__in		int		cchWideChar,
	__out_opt	LPSTR	lpMultiByteStr,
	__in		int		cbMultiByte,
	__in_opt	LPCCH	lpDefaultChar,
	__out_opt	LPBOOL	lpUsedDefaultChar
) {
	DWORD ret = 0;
	if (CodePage == CP_ACP || CodePage == CP_UTF8)
		LOQ_zero("misc", "u", "String", lpWideCharStr);
	return Old_WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

HOOKDEF(LPSTR, WINAPI, GetCommandLineA,
	void
) {
	LPSTR ret = Old_GetCommandLineA();
	LOQ_nonnull("misc", "s", "CommandLine", ret);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, GetCommandLineW,
	void
) {
	LPWSTR ret = Old_GetCommandLineW();
	LOQ_nonnull("misc", "u", "CommandLine", ret);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, CommandLineToArgvW,
	__in LPWSTR lpCmdLine,
	__out int *pNumArgs
) {
	LPWSTR ret = Old_CommandLineToArgvW(lpCmdLine, pNumArgs);
	LOQ_nonnull("misc", "ui", "CommandLine", lpCmdLine, "NumArgs", *pNumArgs);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplayDevicesA,
	_In_	LPCSTR  lpDevice,
	_In_	DWORD  iDevNum,
	_Out_   PDISPLAY_DEVICEA lpDisplayDevice,
	_In_	DWORD  dwFlags
) {
	const char* keywords[] = {
		"microsoft hyper-v video",
		"virtual",
		"vmware",
		"standard vga graphics adapter",
		"microsoft basic display adapter"
	};
	int keywords_size = sizeof(keywords) / sizeof(keywords[0]);

	const char replacement[] = "NVIDIA GeForce RTX 3060";

	BOOL ret = Old_EnumDisplayDevicesA(lpDevice, iDevNum, lpDisplayDevice, dwFlags);
	for (int i = 0; i < keywords_size; i++) {
		if (stristr(lpDisplayDevice->DeviceString, keywords[i]) != NULL) {
			snprintf(lpDisplayDevice->DeviceString, strlen(replacement) + 1, replacement);
			break;
		}
	}
	LOQ_bool("misc", "s", "DeviceString", lpDisplayDevice->DeviceString);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplayDevicesW,
	_In_	LPCWSTR  lpDevice,
	_In_	DWORD  iDevNum,
	_Out_   PDISPLAY_DEVICEW lpDisplayDevice,
	_In_	DWORD  dwFlags
) {
	const wchar_t* keywords[] = {
		L"microsoft hyper-v video",
		L"virtual",
		L"vmware",
		L"standard vga graphics adapter",
		L"microsoft basic display adapter"
	};
	int keywords_size = sizeof(keywords) / sizeof(keywords[0]);

	const wchar_t replacement[] = L"NVIDIA GeForce RTX 3060";

	BOOL ret = Old_EnumDisplayDevicesW(lpDevice, iDevNum, lpDisplayDevice, dwFlags);
	for (int i = 0; i < keywords_size; i++) {
		if (wcsistr(lpDisplayDevice->DeviceString, keywords[i]) != NULL) {
			swprintf(lpDisplayDevice->DeviceString, wcslen(replacement) + 1, replacement);
			break;
		}
	}
	LOQ_bool("misc", "u", "DeviceString", lpDisplayDevice->DeviceString);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiInstallProductA,
	_In_	LPCSTR	szPackagePath,
	_In_	LPCSTR	szCommandLine
) {
	UINT ret = Old_MsiInstallProductA(szPackagePath, szCommandLine);
	LOQ_zero("misc", "ss", "PackagePath", szPackagePath, "CommandLine", szCommandLine);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiInstallProductW,
	_In_	LPCWSTR	szPackagePath,
	_In_	LPCWSTR	szCommandLine
) {
	UINT ret = Old_MsiInstallProductW(szPackagePath, szCommandLine);
	LOQ_zero("misc", "uu", "PackagePath", szPackagePath, "CommandLine", szCommandLine);
	return ret;
}

HOOKDEF(ULONG, __fastcall, vDbgPrintExWithPrefixInternal,
	__in  PCH Prefix,
	__in  ULONG ComponentId,
	__in  ULONG Level,
	__in  PCHAR Format,
	__in  va_list arglist,
	__in  BOOLEAN HandleBreakpoint
) {
    UCHAR Buffer[512];
    size_t cb = strlen(Prefix);
    strcpy(Buffer, Prefix);
    cb = _vsnprintf(Buffer + cb, sizeof(Buffer) - cb, Format, arglist) + cb;

    if (cb == -1) {
        cb = sizeof(Buffer);
        Buffer[sizeof(Buffer) - 1] = '\n';
    }

	DebugOutput("%s", Buffer);

    return Old_vDbgPrintExWithPrefixInternal(Prefix, ComponentId, Level, Format, arglist, HandleBreakpoint);
}

HOOKDEF(DWORD, WINAPI, MapFileAndCheckSumA,
	_In_  PCSTR  Filename,
	_Out_ PDWORD HeaderSum,
	_Out_ PDWORD CheckSum
) {
	DWORD ret = Old_MapFileAndCheckSumA(Filename, HeaderSum, CheckSum);

	if (HeaderSum && CheckSum)
		*CheckSum = *HeaderSum;

	if (HeaderSum && CheckSum)
		LOQ_zero("misc", "fhh", "Filename", Filename, "HeaderSum", *HeaderSum, "CheckSum", *CheckSum);
	else
		LOQ_zero("misc", "f", "Filename", Filename);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtPowerInformation,
	__in		POWER_INFORMATION_LEVEL InformationLevel,
	__in_opt	PVOID                   InputBuffer,
	__in		ULONG                   InputBufferLength,
	__out_opt	PVOID                   OutputBuffer,
	__in		ULONG                   OutputBufferLength
) {
	NTSTATUS ret = Old_NtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	if (ret == 0 && OutputBuffer && InformationLevel == SystemPowerCapabilities && OutputBufferLength >= sizeof(SYSTEM_POWER_CAPABILITIES)) {
		// Most VM systems does not support either S0 or S3 sleep, which can be used to detect the presence of a VM.
		// S0, S4 and S5 being enabled is typical for a normal Modern Standby machine. 
		SYSTEM_POWER_CAPABILITIES* ptr = (SYSTEM_POWER_CAPABILITIES *)OutputBuffer;
		ptr->AoAc = 1;
		ptr->SystemS4 = 1;
		ptr->SystemS5 = 1;
		ptr->ThermalControl = 1;
	}
	LOQ_ntstatus("device", "ibb",
		"InformationLevel", InformationLevel,
		"InputBuffer", InputBufferLength, InputBuffer,
		"OutputBuffer", OutputBufferLength, OutputBuffer);
	return ret;
}


/* ============================================================================
 * MIRAGE2 ADDED HOOKS -- hook_misc.c
 * Auto-generated skeletons from data/api_hook_analysis/unhooked_api_classified.jsonl
 * Added 2026-07-11. Fill in spoofing/filtering logic per API as needed.
 * ============================================================================ */
/* ---- MIRAGE2 REQUIRED TYPE HEADERS ---- */
#include <cfgmgr32.h>
#include <d3d11.h>
#include <winevt.h>
#include <setupapi.h>
#include <objbase.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mmsystem.h>
#include <dbghelp.h>
#include <msi.h>
#include <pdh.h>
#include <powrprof.h>
#include <vfw.h>
#ifndef DIRECTINPUT_VERSION
#define DIRECTINPUT_VERSION 0x0800
#endif
#include <dinput.h>

#include <vfw.h>
#include <cfgmgr32.h>
#include <d3d11.h>
#include <dbghelp.h>
#ifndef DIRECTINPUT_VERSION
#define DIRECTINPUT_VERSION 0x0800
#endif
#include <dinput.h>
#include <wingdi.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <msi.h>
#include <pdh.h>
#include <powrbase.h>
#include <powrprof.h>
#include <setupapi.h>
#include <userenv.h>
#include <winevt.h>
#include <mmsystem.h>
#include <winspool.h>

HOOKDEF(BOOL, WINAPI, AllocConsole
) {
	BOOL ret = Old_AllocConsole();
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, AttachConsole,
	DWORD dwProcessId
) {
	BOOL ret = Old_AttachConsole(dwProcessId);
	LOQ_bool("misc", "i", "DwProcessId", dwProcessId);
	return ret;
}

HOOKDEF(CONFIGRET, WINAPI, CM_Get_DevNode_PropertyW,
	DEVINST dnDevInst,
	const DEVPROPKEY* PropertyKey,
	DEVPROPTYPE* PropertyType,
	PBYTE PropertyBuffer,
	PULONG PropertyBufferSize,
	ULONG ulFlags
) {
	CONFIGRET ret = Old_CM_Get_DevNode_PropertyW(dnDevInst, PropertyKey, PropertyType, PropertyBuffer, PropertyBufferSize, ulFlags);
	LOQ_nonzero("misc", "ippppi", "DnDevInst", dnDevInst, "PropertyKey", PropertyKey, "PropertyType", PropertyType, "PropertyBuffer", PropertyBuffer, "PropertyBufferSize", PropertyBufferSize, "UlFlags", ulFlags);
	return ret;
}

HOOKDEF(CONFIGRET, WINAPI, CM_Get_DevNode_Status,
	PULONG pulStatus,
	PULONG pulProblemNumber,
	DEVINST dnDevInst,
	ULONG ulFlags
) {
	CONFIGRET ret = Old_CM_Get_DevNode_Status(pulStatus, pulProblemNumber, dnDevInst, ulFlags);
	LOQ_nonzero("misc", "ppii", "PulStatus", pulStatus, "PulProblemNumber", pulProblemNumber, "DnDevInst", dnDevInst, "UlFlags", ulFlags);
	return ret;
}

HOOKDEF(CONFIGRET, WINAPI, CM_Get_Device_ID_List_SizeA,
	PULONG pulLen,
	PCSTR pszFilter,
	ULONG ulFlags
) {
	CONFIGRET ret = Old_CM_Get_Device_ID_List_SizeA(pulLen, pszFilter, ulFlags);
	LOQ_nonzero("misc", "psi", "PulLen", pulLen, "PszFilter", pszFilter, "UlFlags", ulFlags);
	return ret;
}

HOOKDEF(CONFIGRET, WINAPI, CM_Get_Device_ID_List_SizeW,
	PULONG pulLen,
	PCWSTR pszFilter,
	ULONG ulFlags
) {
	CONFIGRET ret = Old_CM_Get_Device_ID_List_SizeW(pulLen, pszFilter, ulFlags);
	LOQ_nonzero("misc", "pui", "PulLen", pulLen, "PszFilter", pszFilter, "UlFlags", ulFlags);
	return ret;
}

HOOKDEF(CONFIGRET, WINAPI, CM_Locate_DevNodeA,
	PDEVINST pdnDevInst,
	DEVINSTID_A pDeviceID,
	ULONG ulFlags
) {
	CONFIGRET ret = Old_CM_Locate_DevNodeA(pdnDevInst, pDeviceID, ulFlags);
	LOQ_nonzero("misc", "pii", "PdnDevInst", pdnDevInst, "PDeviceID", pDeviceID, "UlFlags", ulFlags);
	return ret;
}

HOOKDEF(CONFIGRET, WINAPI, CM_Locate_DevNodeW,
	PDEVINST pdnDevInst,
	DEVINSTID_W pDeviceID,
	ULONG ulFlags
) {
	CONFIGRET ret = Old_CM_Locate_DevNodeW(pdnDevInst, pDeviceID, ulFlags);
	LOQ_nonzero("misc", "pii", "PdnDevInst", pdnDevInst, "PDeviceID", pDeviceID, "UlFlags", ulFlags);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, CallNtPowerInformation,
	POWER_INFORMATION_LEVEL InformationLevel,
	PVOID lpInputBuffer,
	ULONG nInputBufferSize,
	PVOID lpOutputBuffer,
	ULONG nOutputBufferSize
) {
	NTSTATUS ret = Old_CallNtPowerInformation(InformationLevel, lpInputBuffer, nInputBufferSize, lpOutputBuffer, nOutputBufferSize);
	LOQ_ntstatus("misc", "ppipi", "InformationLevel", InformationLevel, "LpInputBuffer", lpInputBuffer, "NInputBufferSize", nInputBufferSize, "LpOutputBuffer", lpOutputBuffer, "NOutputBufferSize", nOutputBufferSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CancelIoEx,
	HANDLE hFile,
	LPOVERLAPPED lpOverlapped
) {
	BOOL ret = Old_CancelIoEx(hFile, lpOverlapped);
	LOQ_bool("misc", "pp", "HFile", hFile, "LpOverlapped", lpOverlapped);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CloseHandle,
	HANDLE hObject
) {
	BOOL ret = Old_CloseHandle(hObject);
	LOQ_bool("misc", "p", "HObject", hObject);
	return ret;
}

HOOKDEF(LONG, WINAPI, CompareFileTime,
	const FILETIME* lpFileTime1,
	const FILETIME* lpFileTime2
) {
	LONG ret = Old_CompareFileTime(lpFileTime1, lpFileTime2);
	LOQ_zero("misc", "pp", "LpFileTime1", lpFileTime1, "LpFileTime2", lpFileTime2);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, D3D11CreateDevice,
	IDXGIAdapter* pAdapter,
	D3D_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	const D3D_FEATURE_LEVEL* pFeatureLevels,
	UINT FeatureLevels,
	UINT SDKVersion,
	ID3D11Device** ppDevice,
	D3D_FEATURE_LEVEL* pFeatureLevel,
	ID3D11DeviceContext** ppImmediateContext
) {
	HRESULT ret = Old_D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
	LOQ_hresult("misc", "pipipiippp", "PAdapter", pAdapter, "DriverType", DriverType, "Software", Software, "Flags", Flags, "PFeatureLevels", pFeatureLevels, "FeatureLevels", FeatureLevels, "SDKVersion", SDKVersion, "PpDevice", ppDevice, "PFeatureLevel", pFeatureLevel, "PpImmediateContext", ppImmediateContext);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DirectInput8Create,
	HINSTANCE hinst,
	DWORD dwVersion,
	REFIID riidltf,
	LPVOID* ppvOut,
	LPUNKNOWN punkOuter
) {
	HRESULT ret = Old_DirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
	LOQ_hresult("misc", "piipp", "Hinst", hinst, "DwVersion", dwVersion, "Riidltf", riidltf, "PpvOut", ppvOut, "PunkOuter", punkOuter);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumPrinterDriversA,
	LPSTR pName,
	LPSTR pEnvironment,
	DWORD Level,
	LPBYTE pDriverInfo,
	DWORD cbBuf,
	LPDWORD pcbNeeded,
	LPDWORD pcReturned
) {
	BOOL ret = Old_EnumPrinterDriversA(pName, pEnvironment, Level, pDriverInfo, cbBuf, pcbNeeded, pcReturned);
	LOQ_bool("misc", "ssipipp", "PName", pName, "PEnvironment", pEnvironment, "Level", Level, "PDriverInfo", pDriverInfo, "CbBuf", cbBuf, "PcbNeeded", pcbNeeded, "PcReturned", pcReturned);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumPrinters,
	DWORD Flags,
	LPTSTR Name,
	DWORD Level,
	LPBYTE pPrinterEnum,
	DWORD cbBuf,
	LPDWORD pcbNeeded,
	LPDWORD pcReturned
) {
	BOOL ret = Old_EnumPrinters(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	LOQ_bool("misc", "isipipp", "Flags", Flags, "Name", Name, "Level", Level, "PPrinterEnum", pPrinterEnum, "CbBuf", cbBuf, "PcbNeeded", pcbNeeded, "PcReturned", pcReturned);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumPrintersA,
	DWORD Flags,
	LPSTR Name,
	DWORD Level,
	LPBYTE pPrinterEnum,
	DWORD cbBuf,
	LPDWORD pcbNeeded,
	LPDWORD pcReturned
) {
	BOOL ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	LOQ_bool("misc", "isipipp", "Flags", Flags, "Name", Name, "Level", Level, "PPrinterEnum", pPrinterEnum, "CbBuf", cbBuf, "PcbNeeded", pcbNeeded, "PcReturned", pcReturned);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumPrintersW,
	DWORD Flags,
	LPWSTR Name,
	DWORD Level,
	LPBYTE pPrinterEnum,
	DWORD cbBuf,
	LPDWORD pcbNeeded,
	LPDWORD pcReturned
) {
	BOOL ret = Old_EnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	LOQ_bool("misc", "iuipipp", "Flags", Flags, "Name", Name, "Level", Level, "PPrinterEnum", pPrinterEnum, "CbBuf", cbBuf, "PcbNeeded", pcbNeeded, "PcReturned", pcReturned);
	return ret;
}

HOOKDEF(UINT, WINAPI, EnumSystemFirmwareTables,
	DWORD FirmwareTableProviderSignature,
	PVOID pFirmwareTableEnumBuffer,
	DWORD BufferSize
) {
	UINT ret = Old_EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableEnumBuffer, BufferSize);
	LOQ_nonzero("misc", "ipi", "FirmwareTableProviderSignature", FirmwareTableProviderSignature, "PFirmwareTableEnumBuffer", pFirmwareTableEnumBuffer, "BufferSize", BufferSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EvtClose,
	EVT_HANDLE Object
) {
	BOOL ret = Old_EvtClose(Object);
	LOQ_bool("misc", "i", "Object", Object);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EvtNext,
	EVT_HANDLE ResultSet,
	DWORD EventsSize,
	PEVT_HANDLE Events,
	DWORD Timeout,
	DWORD Flags,
	PDWORD Returned
) {
	BOOL ret = Old_EvtNext(ResultSet, EventsSize, Events, Timeout, Flags, Returned);
	LOQ_bool("misc", "iipiip", "ResultSet", ResultSet, "EventsSize", EventsSize, "Events", Events, "Timeout", Timeout, "Flags", Flags, "Returned", Returned);
	return ret;
}

HOOKDEF(EVT_HANDLE, WINAPI, EvtOpenPublisherEnum,
	EVT_HANDLE Session,
	DWORD Flags
) {
	EVT_HANDLE ret = Old_EvtOpenPublisherEnum(Session, Flags);
	LOQ_nonzero("misc", "ii", "Session", Session, "Flags", Flags);
	return ret;
}

HOOKDEF(EVT_HANDLE, WINAPI, EvtQuery,
	EVT_HANDLE Session,
	LPCWSTR Path,
	LPCWSTR Query,
	DWORD Flags
) {
	EVT_HANDLE ret = Old_EvtQuery(Session, Path, Query, Flags);
	LOQ_nonzero("misc", "iuui", "Session", Session, "Path", Path, "Query", Query, "Flags", Flags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EvtRender,
	EVT_HANDLE Context,
	EVT_HANDLE Fragment,
	DWORD Flags,
	DWORD BufferSize,
	PVOID Buffer,
	PDWORD BufferUsed,
	PDWORD PropertyCount
) {
	BOOL ret = Old_EvtRender(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount);
	LOQ_bool("misc", "iiiippp", "Context", Context, "Fragment", Fragment, "Flags", Flags, "BufferSize", BufferSize, "Buffer", Buffer, "BufferUsed", BufferUsed, "PropertyCount", PropertyCount);
	return ret;
}

HOOKDEF(DWORD, WINAPI, ExpandEnvironmentStringsA,
	LPCSTR lpSrc,
	LPSTR lpDst,
	DWORD nSize
) {
	DWORD ret = Old_ExpandEnvironmentStringsA(lpSrc, lpDst, nSize);
	LOQ_nonzero("misc", "ssi", "LpSrc", lpSrc, "LpDst", lpDst, "NSize", nSize);
	return ret;
}

HOOKDEF(DWORD, WINAPI, ExpandEnvironmentStringsW,
	LPCWSTR lpSrc,
	LPWSTR lpDst,
	DWORD nSize
) {
	DWORD ret = Old_ExpandEnvironmentStringsW(lpSrc, lpDst, nSize);
	LOQ_nonzero("misc", "uui", "LpSrc", lpSrc, "LpDst", lpDst, "NSize", nSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FileTimeToLocalFileTime,
	const FILETIME* lpFileTime,
	LPFILETIME lpLocalFileTime
) {
	BOOL ret = Old_FileTimeToLocalFileTime(lpFileTime, lpLocalFileTime);
	LOQ_bool("misc", "pp", "LpFileTime", lpFileTime, "LpLocalFileTime", lpLocalFileTime);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FileTimeToSystemTime,
	const FILETIME* lpFileTime,
	LPSYSTEMTIME lpSystemTime
) {
	BOOL ret = Old_FileTimeToSystemTime(lpFileTime, lpSystemTime);
	LOQ_bool("misc", "pp", "LpFileTime", lpFileTime, "LpSystemTime", lpSystemTime);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlushConsoleInputBuffer,
	HANDLE hConsoleInput
) {
	BOOL ret = Old_FlushConsoleInputBuffer(hConsoleInput);
	LOQ_bool("misc", "p", "HConsoleInput", hConsoleInput);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FreeEnvironmentStringsW,
	LPWCH penv
) {
	BOOL ret = Old_FreeEnvironmentStringsW(penv);
	LOQ_bool("misc", "u", "Penv", penv);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FreeLibrary,
	HMODULE hLibModule
) {
	BOOL ret = Old_FreeLibrary(hLibModule);
	LOQ_bool("misc", "p", "HLibModule", hLibModule);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameExA,
	COMPUTER_NAME_FORMAT NameType,
	LPSTR lpBuffer,
	LPDWORD nSize
) {
	BOOL ret = Old_GetComputerNameExA(NameType, lpBuffer, nSize);
	LOQ_bool("misc", "isp", "NameType", NameType, "LpBuffer", lpBuffer, "NSize", nSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetConsoleMode,
	HANDLE hConsoleHandle,
	LPDWORD lpMode
) {
	BOOL ret = Old_GetConsoleMode(hConsoleHandle, lpMode);
	LOQ_bool("misc", "pp", "HConsoleHandle", hConsoleHandle, "LpMode", lpMode);
	return ret;
}

HOOKDEF(int, WINAPI, GetDeviceCaps,
	HDC hdc,
	int index
) {
	int ret = Old_GetDeviceCaps(hdc, index);
	LOQ_nonzero("misc", "pi", "Hdc", hdc, "Index", index);
	return ret;
}

HOOKDEF(LPWCH, WINAPI, GetEnvironmentStringsW
) {
	LPWCH ret = Old_GetEnvironmentStringsW();
	LOQ_nonnull("misc", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetEnvironmentVariableA,
	LPCSTR lpName,
	LPSTR lpBuffer,
	DWORD nSize
) {
	DWORD ret = Old_GetEnvironmentVariableA(lpName, lpBuffer, nSize);
	LOQ_nonzero("misc", "ssi", "LpName", lpName, "LpBuffer", lpBuffer, "NSize", nSize);
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetEnvironmentVariableW,
	LPCWSTR lpName,
	LPWSTR lpBuffer,
	DWORD nSize
) {
	DWORD ret = Old_GetEnvironmentVariableW(lpName, lpBuffer, nSize);
	LOQ_nonzero("misc", "uui", "LpName", lpName, "LpBuffer", lpBuffer, "NSize", nSize);
	return ret;
}

HOOKDEF(HMODULE, WINAPI, GetModuleHandle,
	LPCTSTR lpModuleName
) {
	HMODULE ret = Old_GetModuleHandle(lpModuleName);
	LOQ_nonnull("misc", "s", "LpModuleName", lpModuleName);
	return ret;
}

HOOKDEF(HMODULE, WINAPI, GetModuleHandleA,
	LPCSTR lpModuleName
) {
	HMODULE ret = Old_GetModuleHandleA(lpModuleName);
	LOQ_nonnull("misc", "s", "LpModuleName", lpModuleName);
	return ret;
}

HOOKDEF(HMODULE, WINAPI, GetModuleHandleW,
	LPCWSTR lpModuleName
) {
	HMODULE ret = Old_GetModuleHandleW(lpModuleName);
	LOQ_nonnull("misc", "u", "LpModuleName", lpModuleName);
	return ret;
}

HOOKDEF(void, WINAPI, GetNativeSystemInfo,
	LPSYSTEM_INFO lpSystemInfo
) {
	int ret = 0;
	Old_GetNativeSystemInfo(lpSystemInfo);
	LOQ_void("misc", "p", "LpSystemInfo", lpSystemInfo);
	return;
}

HOOKDEF(BOOL, WINAPI, GetNumaHighestNodeNumber,
	PULONG HighestNodeNumber
) {
	BOOL ret = Old_GetNumaHighestNodeNumber(HighestNodeNumber);
	LOQ_bool("misc", "p", "HighestNodeNumber", HighestNodeNumber);
	return ret;
}

HOOKDEF(FARPROC, WINAPI, GetProcAddress,
	HMODULE hModule,
	LPCSTR lpProcName
) {
	FARPROC ret = Old_GetProcAddress(hModule, lpProcName);
	LOQ_nonnull("misc", "ps", "HModule", hModule, "LpProcName", lpProcName);
	return ret;
}

HOOKDEF(BOOLEAN, WINAPI, GetPwrCapabilities,
	PSYSTEM_POWER_CAPABILITIES lpspc
) {
	BOOLEAN ret = Old_GetPwrCapabilities(lpspc);
	LOQ_bool("misc", "p", "Lpspc", lpspc);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetQueuedCompletionStatus,
	HANDLE CompletionPort,
	LPDWORD lpNumberOfBytesTransferred,
	PULONG_PTR lpCompletionKey,
	LPOVERLAPPED* lpOverlapped,
	DWORD dwMilliseconds
) {
	BOOL ret = Old_GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds);
	LOQ_bool("misc", "ppppi", "CompletionPort", CompletionPort, "LpNumberOfBytesTransferred", lpNumberOfBytesTransferred, "LpCompletionKey", lpCompletionKey, "LpOverlapped", lpOverlapped, "DwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, GetStdHandle,
	DWORD nStdHandle
) {
	HANDLE ret = Old_GetStdHandle(nStdHandle);
	LOQ_handle("misc", "i", "NStdHandle", nStdHandle);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetSystemDirectoryA,
	LPSTR lpBuffer,
	UINT uSize
) {
	UINT ret = Old_GetSystemDirectoryA(lpBuffer, uSize);
	LOQ_nonzero("misc", "si", "LpBuffer", lpBuffer, "USize", uSize);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetSystemDirectoryW,
	LPWSTR lpBuffer,
	UINT uSize
) {
	UINT ret = Old_GetSystemDirectoryW(lpBuffer, uSize);
	LOQ_nonzero("misc", "ui", "LpBuffer", lpBuffer, "USize", uSize);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetSystemFirmwareTable,
	DWORD FirmwareTableProviderSignature,
	DWORD FirmwareTableID,
	PVOID pFirmwareTableBuffer,
	DWORD BufferSize
) {
	UINT ret = Old_GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
	LOQ_nonzero("misc", "iipi", "FirmwareTableProviderSignature", FirmwareTableProviderSignature, "FirmwareTableID", FirmwareTableID, "PFirmwareTableBuffer", pFirmwareTableBuffer, "BufferSize", BufferSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus,
	LPSYSTEM_POWER_STATUS lpSystemPowerStatus
) {
	BOOL ret = Old_GetSystemPowerStatus(lpSystemPowerStatus);
	LOQ_bool("misc", "p", "LpSystemPowerStatus", lpSystemPowerStatus);
	return ret;
}

HOOKDEF(void, WINAPI, GetSystemTimePreciseAsFileTime,
	LPFILETIME lpSystemTimeAsFileTime
) {
	int ret = 0;
	Old_GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);
	LOQ_void("misc", "p", "LpSystemTimeAsFileTime", lpSystemTimeAsFileTime);
	return;
}

HOOKDEF(BOOL, WINAPI, GetSystemTimes,
	PFILETIME lpIdleTime,
	PFILETIME lpKernelTime,
	PFILETIME lpUserTime
) {
	BOOL ret = Old_GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime);
	LOQ_bool("misc", "ppp", "LpIdleTime", lpIdleTime, "LpKernelTime", lpKernelTime, "LpUserTime", lpUserTime);
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetTimeZoneInformation,
	LPTIME_ZONE_INFORMATION lpTimeZoneInformation
) {
	DWORD ret = Old_GetTimeZoneInformation(lpTimeZoneInformation);
	LOQ_nonzero("misc", "p", "LpTimeZoneInformation", lpTimeZoneInformation);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserProfileDirectoryW,
	HANDLE hToken,
	LPWSTR lpProfileDir,
	LPDWORD lpcchSize
) {
	BOOL ret = Old_GetUserProfileDirectoryW(hToken, lpProfileDir, lpcchSize);
	LOQ_bool("misc", "pup", "HToken", hToken, "LpProfileDir", lpProfileDir, "LpcchSize", lpcchSize);
	return ret;
}

HOOKDEF(HMODULE, WINAPI, LoadLibraryA,
	LPCSTR lpLibFileName
) {
	HMODULE ret = Old_LoadLibraryA(lpLibFileName);
	LOQ_nonnull("misc", "s", "LpLibFileName", lpLibFileName);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, MFCreateAttributes,
	IMFAttributes** ppMFAttributes,
	UINT32 cInitialSize
) {
	HRESULT ret = Old_MFCreateAttributes(ppMFAttributes, cInitialSize);
	LOQ_hresult("misc", "pi", "PpMFAttributes", ppMFAttributes, "CInitialSize", cInitialSize);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, MFEnumDeviceSources,
	IMFAttributes* pAttributes,
	IMFActivate*** pppSourceActivate,
	UINT32* pcSourceActivate
) {
	HRESULT ret = Old_MFEnumDeviceSources(pAttributes, pppSourceActivate, pcSourceActivate);
	LOQ_hresult("misc", "ppp", "PAttributes", pAttributes, "PppSourceActivate", pppSourceActivate, "PcSourceActivate", pcSourceActivate);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, MFShutdown
) {
	HRESULT ret = Old_MFShutdown();
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, MFStartup,
	ULONG Version,
	DWORD dwFlags
) {
	HRESULT ret = Old_MFStartup(Version, dwFlags);
	LOQ_hresult("misc", "ii", "Version", Version, "DwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, MiniDumpWriteDump,
	HANDLE hProcess,
	DWORD ProcessId,
	HANDLE hFile,
	MINIDUMP_TYPE DumpType,
	PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	PMINIDUMP_CALLBACK_INFORMATION CallbackParam
) {
	BOOL ret = Old_MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);
	LOQ_bool("misc", "pipippp", "HProcess", hProcess, "ProcessId", ProcessId, "HFile", hFile, "DumpType", DumpType, "ExceptionParam", ExceptionParam, "UserStreamParam", UserStreamParam, "CallbackParam", CallbackParam);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiEnumProductsA,
	DWORD iProductIndex,
	LPSTR lpProductBuf
) {
	UINT ret = Old_MsiEnumProductsA(iProductIndex, lpProductBuf);
	LOQ_nonzero("misc", "is", "IProductIndex", iProductIndex, "LpProductBuf", lpProductBuf);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiEnumProductsExW,
	LPCWSTR szProductCode,
	LPCWSTR szUserSid,
	DWORD dwContext,
	DWORD dwIndex,
	WCHAR* szInstalledProductCode,
	MSIINSTALLCONTEXT* pdwInstalledContext,
	LPWSTR szSid,
	LPDWORD pcchSid
) {
	UINT ret = Old_MsiEnumProductsExW(szProductCode, szUserSid, dwContext, dwIndex, szInstalledProductCode, pdwInstalledContext, szSid, pcchSid);
	LOQ_nonzero("misc", "uuiiupup", "SzProductCode", szProductCode, "SzUserSid", szUserSid, "DwContext", dwContext, "DwIndex", dwIndex, "SzInstalledProductCode", szInstalledProductCode, "PdwInstalledContext", pdwInstalledContext, "SzSid", szSid, "PcchSid", pcchSid);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiEnumProductsW,
	DWORD iProductIndex,
	LPWSTR lpProductBuf
) {
	UINT ret = Old_MsiEnumProductsW(iProductIndex, lpProductBuf);
	LOQ_nonzero("misc", "iu", "IProductIndex", iProductIndex, "LpProductBuf", lpProductBuf);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiGetProductInfoA,
	LPCSTR szProduct,
	LPCSTR szProperty,
	LPSTR lpValueBuf,
	LPDWORD pcchValueBuf
) {
	UINT ret = Old_MsiGetProductInfoA(szProduct, szProperty, lpValueBuf, pcchValueBuf);
	LOQ_nonzero("misc", "sssp", "SzProduct", szProduct, "SzProperty", szProperty, "LpValueBuf", lpValueBuf, "PcchValueBuf", pcchValueBuf);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiGetProductInfoW,
	LPCWSTR szProduct,
	LPCWSTR szProperty,
	LPWSTR lpValueBuf,
	LPDWORD pcchValueBuf
) {
	UINT ret = Old_MsiGetProductInfoW(szProduct, szProperty, lpValueBuf, pcchValueBuf);
	LOQ_nonzero("misc", "uuup", "SzProduct", szProduct, "SzProperty", szProperty, "LpValueBuf", lpValueBuf, "PcchValueBuf", pcchValueBuf);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhAddCounterA,
	PDH_HQUERY hQuery,
	LPCSTR szFullCounterPath,
	DWORD_PTR dwUserData,
	PDH_HCOUNTER* phCounter
) {
	PDH_STATUS ret = Old_PdhAddCounterA(hQuery, szFullCounterPath, dwUserData, phCounter);
	LOQ_nonnull("misc", "psip", "HQuery", hQuery, "SzFullCounterPath", szFullCounterPath, "DwUserData", dwUserData, "PhCounter", phCounter);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhAddCounterW,
	PDH_HQUERY hQuery,
	LPCWSTR szFullCounterPath,
	DWORD_PTR dwUserData,
	PDH_HCOUNTER* phCounter
) {
	PDH_STATUS ret = Old_PdhAddCounterW(hQuery, szFullCounterPath, dwUserData, phCounter);
	LOQ_nonnull("misc", "puip", "HQuery", hQuery, "SzFullCounterPath", szFullCounterPath, "DwUserData", dwUserData, "PhCounter", phCounter);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhAddEnglishCounter,
	PDH_HQUERY hQuery,
	LPCTSTR szFullCounterPath,
	DWORD_PTR dwUserData,
	PDH_HCOUNTER* phCounter
) {
	PDH_STATUS ret = Old_PdhAddEnglishCounter(hQuery, szFullCounterPath, dwUserData, phCounter);
	LOQ_nonnull("misc", "psip", "HQuery", hQuery, "SzFullCounterPath", szFullCounterPath, "DwUserData", dwUserData, "PhCounter", phCounter);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhAddEnglishCounterA,
	PDH_HQUERY hQuery,
	LPCSTR szFullCounterPath,
	DWORD_PTR dwUserData,
	PDH_HCOUNTER* phCounter
) {
	PDH_STATUS ret = Old_PdhAddEnglishCounterA(hQuery, szFullCounterPath, dwUserData, phCounter);
	LOQ_nonnull("misc", "psip", "HQuery", hQuery, "SzFullCounterPath", szFullCounterPath, "DwUserData", dwUserData, "PhCounter", phCounter);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhAddEnglishCounterW,
	PDH_HQUERY hQuery,
	LPCWSTR szFullCounterPath,
	DWORD_PTR dwUserData,
	PDH_HCOUNTER* phCounter
) {
	PDH_STATUS ret = Old_PdhAddEnglishCounterW(hQuery, szFullCounterPath, dwUserData, phCounter);
	LOQ_nonnull("misc", "puip", "HQuery", hQuery, "SzFullCounterPath", szFullCounterPath, "DwUserData", dwUserData, "PhCounter", phCounter);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhCloseQuery,
	PDH_HQUERY hQuery
) {
	PDH_STATUS ret = Old_PdhCloseQuery(hQuery);
	LOQ_nonnull("misc", "p", "HQuery", hQuery);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhCollectQueryData,
	PDH_HQUERY hQuery
) {
	PDH_STATUS ret = Old_PdhCollectQueryData(hQuery);
	LOQ_nonnull("misc", "p", "HQuery", hQuery);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhGetFormattedCounterValue,
	PDH_HCOUNTER hCounter,
	DWORD dwFormat,
	LPDWORD lpdwType,
	PPDH_FMT_COUNTERVALUE pValue
) {
	PDH_STATUS ret = Old_PdhGetFormattedCounterValue(hCounter, dwFormat, lpdwType, pValue);
	LOQ_nonnull("misc", "pipp", "HCounter", hCounter, "DwFormat", dwFormat, "LpdwType", lpdwType, "PValue", pValue);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhOpenQuery,
	LPCTSTR szDataSource,
	DWORD_PTR dwUserData,
	PDH_HQUERY* phQuery
) {
	PDH_STATUS ret = Old_PdhOpenQuery(szDataSource, dwUserData, phQuery);
	LOQ_nonnull("misc", "sip", "SzDataSource", szDataSource, "DwUserData", dwUserData, "PhQuery", phQuery);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhOpenQueryA,
	LPCSTR szDataSource,
	DWORD_PTR dwUserData,
	PDH_HQUERY* phQuery
) {
	PDH_STATUS ret = Old_PdhOpenQueryA(szDataSource, dwUserData, phQuery);
	LOQ_nonnull("misc", "sip", "SzDataSource", szDataSource, "DwUserData", dwUserData, "PhQuery", phQuery);
	return ret;
}

HOOKDEF(PDH_STATUS, WINAPI, PdhOpenQueryW,
	LPCWSTR szDataSource,
	DWORD_PTR dwUserData,
	PDH_HQUERY* phQuery
) {
	PDH_STATUS ret = Old_PdhOpenQueryW(szDataSource, dwUserData, phQuery);
	LOQ_nonnull("misc", "uip", "SzDataSource", szDataSource, "DwUserData", dwUserData, "PhQuery", phQuery);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekConsoleInput,
	HANDLE hConsoleInput,
	PINPUT_RECORD lpBuffer,
	DWORD nLength,
	LPDWORD lpNumberOfEventsRead
) {
	BOOL ret = Old_PeekConsoleInput(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	LOQ_bool("misc", "ppip", "HConsoleInput", hConsoleInput, "LpBuffer", lpBuffer, "NLength", nLength, "LpNumberOfEventsRead", lpNumberOfEventsRead);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekConsoleInputA,
	HANDLE hConsoleInput,
	PINPUT_RECORD lpBuffer,
	DWORD nLength,
	LPDWORD lpNumberOfEventsRead
) {
	BOOL ret = Old_PeekConsoleInputA(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	LOQ_bool("misc", "ppip", "HConsoleInput", hConsoleInput, "LpBuffer", lpBuffer, "NLength", nLength, "LpNumberOfEventsRead", lpNumberOfEventsRead);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PostQueuedCompletionStatus,
	HANDLE CompletionPort,
	DWORD dwNumberOfBytesTransferred,
	ULONG_PTR dwCompletionKey,
	LPOVERLAPPED lpOverlapped
) {
	BOOL ret = Old_PostQueuedCompletionStatus(CompletionPort, dwNumberOfBytesTransferred, dwCompletionKey, lpOverlapped);
	LOQ_bool("misc", "piip", "CompletionPort", CompletionPort, "DwNumberOfBytesTransferred", dwNumberOfBytesTransferred, "DwCompletionKey", dwCompletionKey, "LpOverlapped", lpOverlapped);
	return ret;
}

HOOKDEF(void, WINAPI, QueryInterruptTimePrecise,
	PULONGLONG lpInterruptTimePrecise
) {
	int ret = 0;
	Old_QueryInterruptTimePrecise(lpInterruptTimePrecise);
	LOQ_void("misc", "p", "LpInterruptTimePrecise", lpInterruptTimePrecise);
	return;
}

HOOKDEF(BOOL, WINAPI, QueryPerformanceCounter,
	LARGE_INTEGER* lpPerformanceCount
) {
	BOOL ret = Old_QueryPerformanceCounter(lpPerformanceCount);
	LOQ_bool("misc", "p", "LpPerformanceCount", lpPerformanceCount);
	return ret;
}

HOOKDEF(BOOL, WINAPI, QueryPerformanceFrequency,
	LARGE_INTEGER* lpFrequency
) {
	BOOL ret = Old_QueryPerformanceFrequency(lpFrequency);
	LOQ_bool("misc", "p", "LpFrequency", lpFrequency);
	return ret;
}

HOOKDEF(BOOL, WINAPI, QueryUnbiasedInterruptTime,
	PULONGLONG UnbiasedTime
) {
	BOOL ret = Old_QueryUnbiasedInterruptTime(UnbiasedTime);
	LOQ_bool("misc", "p", "UnbiasedTime", UnbiasedTime);
	return ret;
}

HOOKDEF(void, WINAPI, QueryUnbiasedInterruptTimePrecise,
	PULONGLONG lpUnbiasedInterruptTimePrecise
) {
	int ret = 0;
	Old_QueryUnbiasedInterruptTimePrecise(lpUnbiasedInterruptTimePrecise);
	LOQ_void("misc", "p", "LpUnbiasedInterruptTimePrecise", lpUnbiasedInterruptTimePrecise);
	return;
}

HOOKDEF(BOOL, WINAPI, ReadConsoleInput,
	HANDLE hConsoleInput,
	PINPUT_RECORD lpBuffer,
	DWORD nLength,
	LPDWORD lpNumberOfEventsRead
) {
	BOOL ret = Old_ReadConsoleInput(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	LOQ_bool("misc", "ppip", "HConsoleInput", hConsoleInput, "LpBuffer", lpBuffer, "NLength", nLength, "LpNumberOfEventsRead", lpNumberOfEventsRead);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ReadConsoleInputA,
	HANDLE hConsoleInput,
	PINPUT_RECORD lpBuffer,
	DWORD nLength,
	LPDWORD lpNumberOfEventsRead
) {
	BOOL ret = Old_ReadConsoleInputA(hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	LOQ_bool("misc", "ppip", "HConsoleInput", hConsoleInput, "LpBuffer", lpBuffer, "NLength", nLength, "LpNumberOfEventsRead", lpNumberOfEventsRead);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetConsoleCtrlHandler,
	PHANDLER_ROUTINE HandlerRoutine,
	BOOL Add
) {
	BOOL ret = Old_SetConsoleCtrlHandler(HandlerRoutine, Add);
	LOQ_bool("misc", "pi", "HandlerRoutine", HandlerRoutine, "Add", Add);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetConsoleMode,
	HANDLE hConsoleHandle,
	DWORD dwMode
) {
	BOOL ret = Old_SetConsoleMode(hConsoleHandle, dwMode);
	LOQ_bool("misc", "pi", "HConsoleHandle", hConsoleHandle, "DwMode", dwMode);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetHandleInformation,
	HANDLE hObject,
	DWORD dwMask,
	DWORD dwFlags
) {
	BOOL ret = Old_SetHandleInformation(hObject, dwMask, dwFlags);
	LOQ_bool("misc", "pii", "HObject", hObject, "DwMask", dwMask, "DwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiDestroyDeviceInfoList,
	HDEVINFO DeviceInfoSet
) {
	BOOL ret = Old_SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	LOQ_bool("misc", "p", "DeviceInfoSet", DeviceInfoSet);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiEnumDeviceInfo,
	HDEVINFO DeviceInfoSet,
	DWORD MemberIndex,
	PSP_DEVINFO_DATA DeviceInfoData
) {
	BOOL ret = Old_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);
	LOQ_bool("misc", "pip", "DeviceInfoSet", DeviceInfoSet, "MemberIndex", MemberIndex, "DeviceInfoData", DeviceInfoData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiEnumDeviceInterfaces,
	HDEVINFO DeviceInfoSet,
	PSP_DEVINFO_DATA DeviceInfoData,
	const GUID* InterfaceClassGuid,
	DWORD MemberIndex,
	PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
) {
	BOOL ret = Old_SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData);
	LOQ_bool("misc", "pppip", "DeviceInfoSet", DeviceInfoSet, "DeviceInfoData", DeviceInfoData, "InterfaceClassGuid", InterfaceClassGuid, "MemberIndex", MemberIndex, "DeviceInterfaceData", DeviceInterfaceData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceInstanceIdA,
	HDEVINFO DeviceInfoSet,
	PSP_DEVINFO_DATA DeviceInfoData,
	PSTR DeviceInstanceId,
	DWORD DeviceInstanceIdSize,
	PDWORD RequiredSize
) {
	BOOL ret = Old_SetupDiGetDeviceInstanceIdA(DeviceInfoSet, DeviceInfoData, DeviceInstanceId, DeviceInstanceIdSize, RequiredSize);
	LOQ_bool("misc", "ppsip", "DeviceInfoSet", DeviceInfoSet, "DeviceInfoData", DeviceInfoData, "DeviceInstanceId", DeviceInstanceId, "DeviceInstanceIdSize", DeviceInstanceIdSize, "RequiredSize", RequiredSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceInterfaceDetail,
	HDEVINFO DeviceInfoSet,
	PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
	PSP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData,
	DWORD DeviceInterfaceDetailDataSize,
	PDWORD RequiredSize,
	PSP_DEVINFO_DATA DeviceInfoData
) {
	BOOL ret = Old_SetupDiGetDeviceInterfaceDetail(DeviceInfoSet, DeviceInterfaceData, DeviceInterfaceDetailData, DeviceInterfaceDetailDataSize, RequiredSize, DeviceInfoData);
	LOQ_bool("misc", "pppipp", "DeviceInfoSet", DeviceInfoSet, "DeviceInterfaceData", DeviceInterfaceData, "DeviceInterfaceDetailData", DeviceInterfaceDetailData, "DeviceInterfaceDetailDataSize", DeviceInterfaceDetailDataSize, "RequiredSize", RequiredSize, "DeviceInfoData", DeviceInfoData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceInterfaceDetailA,
	HDEVINFO DeviceInfoSet,
	PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
	PSP_DEVICE_INTERFACE_DETAIL_DATA_A DeviceInterfaceDetailData,
	DWORD DeviceInterfaceDetailDataSize,
	PDWORD RequiredSize,
	PSP_DEVINFO_DATA DeviceInfoData
) {
	BOOL ret = Old_SetupDiGetDeviceInterfaceDetailA(DeviceInfoSet, DeviceInterfaceData, DeviceInterfaceDetailData, DeviceInterfaceDetailDataSize, RequiredSize, DeviceInfoData);
	LOQ_bool("misc", "pppipp", "DeviceInfoSet", DeviceInfoSet, "DeviceInterfaceData", DeviceInterfaceData, "DeviceInterfaceDetailData", DeviceInterfaceDetailData, "DeviceInterfaceDetailDataSize", DeviceInterfaceDetailDataSize, "RequiredSize", RequiredSize, "DeviceInfoData", DeviceInfoData);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemTimeToFileTime,
	const SYSTEMTIME* lpSystemTime,
	LPFILETIME lpFileTime
) {
	BOOL ret = Old_SystemTimeToFileTime(lpSystemTime, lpFileTime);
	LOQ_bool("misc", "pp", "LpSystemTime", lpSystemTime, "LpFileTime", lpFileTime);
	return ret;
}

HOOKDEF(BOOL, WINAPI, TzSpecificLocalTimeToSystemTime,
	const TIME_ZONE_INFORMATION* lpTimeZoneInformation,
	const SYSTEMTIME* lpLocalTime,
	LPSYSTEMTIME lpUniversalTime
) {
	BOOL ret = Old_TzSpecificLocalTimeToSystemTime(lpTimeZoneInformation, lpLocalTime, lpUniversalTime);
	LOQ_bool("misc", "ppp", "LpTimeZoneInformation", lpTimeZoneInformation, "LpLocalTime", lpLocalTime, "LpUniversalTime", lpUniversalTime);
	return ret;
}

HOOKDEF(BOOL, WINAPI, capGetDriverDescriptionA,
	WORD wDriverIndex,
	LPSTR lpszName,
	int cbName,
	LPSTR lpszVer,
	int cbVer
) {
	BOOL ret = Old_capGetDriverDescriptionA(wDriverIndex, lpszName, cbName, lpszVer, cbVer);
	LOQ_bool("misc", "isisi", "WDriverIndex", wDriverIndex, "LpszName", lpszName, "CbName", cbName, "LpszVer", lpszVer, "CbVer", cbVer);
	return ret;
}

HOOKDEF(int, WINAPI, lstrlenA,
	LPCSTR lpString
) {
	int ret = Old_lstrlenA(lpString);
	LOQ_nonzero("misc", "s", "LpString", lpString);
	return ret;
}

HOOKDEF(int, WINAPI, lstrlenW,
	LPCWSTR lpString
) {
	int ret = Old_lstrlenW(lpString);
	LOQ_nonzero("misc", "u", "LpString", lpString);
	return ret;
}

HOOKDEF(BOOL, WINAPI, sndPlaySoundA,
	LPCSTR pszSound,
	UINT fuSound
) {
	BOOL ret = Old_sndPlaySoundA(pszSound, fuSound);
	LOQ_bool("misc", "si", "PszSound", pszSound, "FuSound", fuSound);
	return ret;
}

HOOKDEF(MMRESULT, WINAPI, timeBeginPeriod,
	UINT uPeriod
) {
	MMRESULT ret = Old_timeBeginPeriod(uPeriod);
	LOQ_nonzero("misc", "i", "UPeriod", uPeriod);
	return ret;
}

HOOKDEF(MMRESULT, WINAPI, timeEndPeriod,
	UINT uPeriod
) {
	MMRESULT ret = Old_timeEndPeriod(uPeriod);
	LOQ_nonzero("misc", "i", "UPeriod", uPeriod);
	return ret;
}

HOOKDEF(MMRESULT, WINAPI, timeGetDevCaps,
	LPTIMECAPS ptc,
	UINT cbtc
) {
	MMRESULT ret = Old_timeGetDevCaps(ptc, cbtc);
	LOQ_nonzero("misc", "pi", "Ptc", ptc, "Cbtc", cbtc);
	return ret;
}
