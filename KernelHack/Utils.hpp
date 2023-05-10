/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#pragma once
#include "Includes.h"
#include "NativeStructs.h"

namespace Utils
{
	PVOID GetModuleBase(
		PCHAR szModuleName);

	PVOID GetModuleBase(
		PCHAR szModuleName,
		SIZE_T* size);

	PVOID GetModuleBase(
		PCHAR szModuleName,
		SIZE_T* size,
		BOOLEAN CaseInSensitive);

	PVOID GetModuleBaseEx(
		PCHAR szModuleName);

	PVOID GetModuleBaseEx(
		PCHAR szModuleName,
		SIZE_T* size);

	PVOID GetProcAddress(
		PVOID ModuleBase, 
		PCHAR szFuncName);

	BOOLEAN RtlCaptureAnsiString(
		PUNICODE_STRING, 
		PCSZ, 
		BOOLEAN);

	ULONG GetActiveProcessLinksOffset();

	HANDLE GetProcessIdByName(
		PCHAR szName);

	PEPROCESS GetProcessByProcessId(
		HANDLE pid);

	PEPROCESS GetProcessByProcessIdEx(
		HANDLE pid);

	PVOID GetProcessBaseAddress(
		HANDLE pid);

	PEPROCESS GetProcessByName(
		PCHAR szName);

	PETHREAD GetProcessMainThread(
		PEPROCESS Process);	

	ULONG64 FindPattern(
		ULONG64 base, 
		SIZE_T size, 
		PCHAR pattern,
		PCHAR mask);

	ULONG64 FindPatternImage(
		PCHAR module,
		PCHAR section,
		PCHAR pattern,
		PCHAR mask);

	ULONG64 FindPattern(
		ULONG64 base, 
		SIZE_T size, 
		PCHAR pattern);

	ULONG64 FindPatternImage(
		PCHAR module, 
		PCHAR section, 
		PCHAR pattern);

	ULONG64 GetImageSectionByName(
		ULONG64 imageBase,
		PCHAR sectionName,
		SIZE_T* sizeOut);

	PSERVICE_DESCRIPTOR_TABLE 
		GetKeServiceDescriptorTableShadow();

	PVOID GetServiceFunctionByIndex(
		PSYSTEM_SERVICE_TABLE,
		ULONG ServiceId);

	VOID Sleep(
		ULONG Milliseconds);

	NTSTATUS SafeCmRegisterCallback(
		PEX_CALLBACK_FUNCTION  Function,
		PVOID Context,
		PLARGE_INTEGER Cookie);

	NTSTATUS SafeCmUnRegisterCallback(
		LARGE_INTEGER Cookie);

	PDRIVER_OBJECT GetDriverObjectByName(
		PWCHAR DriverName);

#pragma warning(disable:4127)
	template<class T> T __ROL__(T value, int count)
	{
		const unsigned int nbits = sizeof(T) * 8;
		if (count > 0)
		{
			count %= nbits;
			T high = value >> (nbits - count);
			if (T(-1) < 0) // This will be a signed val.
				high &= ~((T(-1) << count));
			value <<= count;
			value |= high;
		}
		else
		{
			count = -count % nbits;
			T low = value << (nbits - count);
			value >>= count;
			value |= low;
		}
		return value;
	}
};
