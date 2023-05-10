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

namespace Memory
{
	VOID InitializePageBase();

	PMMPTE GetPxeAddress(ULONG64 va);

	PMMPTE GetPpeAddress(ULONG64 va);

	PMMPTE GetPdeAddress(ULONG64 va);

	PMMPTE GetPteAddress(ULONG64 va);

	NTSTATUS ReadPhysicalMemory(
		PHYSICAL_ADDRESS PhysicalAddress,
		PVOID lpBuffer, 
		SIZE_T Size);

	NTSTATUS WritePhysicalMemory(
		PHYSICAL_ADDRESS PhysicalAddress, 
		PVOID lpBuffer, 
		SIZE_T Size);

	ULONG64 GetProcessDirbase(
		PEPROCESS Process);

	PHYSICAL_ADDRESS TranslateLinearAddress(
		ULONG64 Dirbase, 
		ULONG64 VirtualAddress);

	NTSTATUS ReadVirtualMemory(
		ULONG64 Dirbase, 
		PVOID VirtualAddress, 
		PVOID buffer,
		SIZE_T size);

	NTSTATUS WriteVirtualMemory(
		ULONG64 Dirbase,
		PVOID VirtualAddress, 
		PVOID buffer, 
		SIZE_T size);

	NTSTATUS ReadProcessMemory(
		PEPROCESS Process, 
		PVOID VirtualAddress, 
		PVOID lpBuffer, 
		SIZE_T Size);

	NTSTATUS WriteProcessMemory(
		PEPROCESS Process,
		PVOID VirtualAddress,
		PVOID lpBuffer,
		SIZE_T Size);

	NTSTATUS MmAllocateCopyRemove(
		PVOID SrcPtr,
		ULONG DataSize,
		PPHYSICAL_ADDRESS PhysPtr);

	PVOID AllocateMemoryInSystemSpace(
		SIZE_T Size);

	PVOID MmAllocateIndependentPages(
		SIZE_T NumberOfBytes,
		ULONG Node);

	BOOLEAN MmSetPageProtection(
		PVOID VirtualAddress, 
		SIZE_T NumberOfBytes, 
		ULONG NewProtect);

	PHYSICAL_ADDRESS SafeMmGetPhysicalAddress(
		PVOID VirtualAddress);

	BOOLEAN ClearPFN(
		PMDL mdl);

	NTSTATUS CleanPiDDBCache(
		PDRIVER_OBJECT DriverObject);

	NTSTATUS CleanBigPoolAllocation(
		PVOID AllocationAddress);

	BOOLEAN WriteToReadOnly(
		PVOID destination,
		PVOID buffer,
		ULONG size);
	
	BOOLEAN SetExecutePage(
		ULONG64 VirtualAddress,
		SIZE_T size);

};
