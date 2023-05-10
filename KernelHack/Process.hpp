/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#pragma once
#include "Includes.h"

namespace Process
{
	void AttachProcess(
		PEPROCESS NewProcess);

	void DetachProcess();

	NTSTATUS ReadVirtualMemory(
		PEPROCESS Process,
		PVOID Destination,
		PVOID Source,
		SIZE_T Size);

	NTSTATUS WriteVirtualMemory(
		PEPROCESS Process,
		PVOID Destination,
		PVOID Source,
		SIZE_T Size);

	NTSTATUS AllocateVirtualMemory(
		PEPROCESS Process,
		PVOID* BaseAddress,
		SIZE_T* Size,
		DWORD fProtect);

	NTSTATUS FreeVirtualMemory(
		PEPROCESS Process,
		PVOID* BaseAddress,
		SIZE_T* Size);

	NTSTATUS SafeAllocateExecuteMemory(
		PEPROCESS Process,
		PVOID* BaseAddress,
		SIZE_T* Size);

	PVOID GetModuleBase(
		PCHAR ModuleName);
	
	PVOID GetModuleBase(
		PEPROCESS Process,
		PCHAR ModuleName);

	PVOID ProtectProcess(
		PEPROCESS Process);

	PETHREAD GetProcessMainThread(
		PEPROCESS Process);

	KTRAP_FRAME GetThreadTrapFrame(
		PETHREAD Thread);

	void SetThreadTrapFrame(
		PETHREAD Thread, KTRAP_FRAME TrapFrame);

	BOOLEAN InjectShellcode(
		PEPROCESS Process,
		PBYTE Shellcode,
		SIZE_T Size);
};

