/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Utils.hpp"
#include "Imports.h"
#include "Memory.hpp"
#include "Offsets.hpp"
#include "skCrypter.h"

PVOID Utils::GetModuleBase(PCHAR szModuleName)
{
	PVOID result = 0;
	ULONG length = 0;

	ZwQuerySystemInformation(SystemModuleInformation, &length, 0, &length);
	if (!length) return result;

	const unsigned long tag = 'MEM';
	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (!system_modules) return result;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, system_modules, length, 0);
	if (NT_SUCCESS(status))
	{
		for (size_t i = 0; i < system_modules->ulModuleCount; i++)
		{
			char* fileName = (char*)system_modules->Modules[i].ImageName + system_modules->Modules[i].ModuleNameOffset;
			if (!strcmp(fileName, szModuleName))
			{
				result = system_modules->Modules[i].Base;
				break;
			}
		}
	}
	ExFreePoolWithTag(system_modules, tag);
	return result;
}

PVOID Utils::GetModuleBase(PCHAR szModuleName,SIZE_T* size)
{
	PVOID result = 0;
	ULONG length = 0;

	ZwQuerySystemInformation(SystemModuleInformation, &length, 0, &length);
	if (!length) return result;

	const unsigned long tag = 'MEM';
	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (!system_modules) return result;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, system_modules, length, 0);
	if (NT_SUCCESS(status))
	{
		for (size_t i = 0; i < system_modules->ulModuleCount; i++)
		{
			char* fileName = (char*)system_modules->Modules[i].ImageName + system_modules->Modules[i].ModuleNameOffset;
			if (!strcmp(fileName, szModuleName))
			{
				result = system_modules->Modules[i].Base;
                *size = system_modules->Modules[i].Size;
				break;
			}
		}
	}
	ExFreePoolWithTag(system_modules, tag);
	return result;
}

PVOID Utils::GetModuleBase(PCHAR szModuleName, SIZE_T* size, BOOLEAN CaseInSensitive)
{
	PVOID result = 0;
	ULONG length = 0;

	ZwQuerySystemInformation(SystemModuleInformation, &length, 0, &length);
	if (!length) return result;

	const unsigned long tag = 'MEM';
	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (!system_modules) return result;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, system_modules, length, 0);
	if (NT_SUCCESS(status))
	{
		ANSI_STRING str1 = { 0 };
        RtlInitAnsiString(&str1, szModuleName);
		for (size_t i = 0; i < system_modules->ulModuleCount; i++)
		{
			ANSI_STRING str2 = { 0 };
            RtlInitAnsiString(&str2, (char*)system_modules->Modules[i].ImageName + system_modules->Modules[i].ModuleNameOffset);
			if (!RtlCompareString(&str1, &str2, CaseInSensitive))
			{
				result = system_modules->Modules[i].Base;
				*size = system_modules->Modules[i].Size;
				break;
			}
		}
	}
	ExFreePoolWithTag(system_modules, tag);
	return result;
}

BOOLEAN Utils::RtlCaptureAnsiString(PUNICODE_STRING DestinationString, PCSZ SourceString, BOOLEAN AllocateDestinationString)
{
    ANSI_STRING ansi_string = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    RtlInitAnsiString(&ansi_string, SourceString);
    status = RtlAnsiStringToUnicodeString(DestinationString, &ansi_string, AllocateDestinationString);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    return TRUE;
}

PVOID Utils::GetModuleBaseEx(PCHAR szModuleName)
{
    UNICODE_STRING uName = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    PLIST_ENTRY PsLoadedModuleList, NextEntry;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    UNICODE_STRING uModuleName = { 0 };
    
    PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&uName);
    if (!MmIsAddressValid(PsLoadedModuleList))
    {
        return NULL;
    }
    RtlCaptureAnsiString(&uModuleName, szModuleName, TRUE);

    /* Lookup the new Ldr entry in PsLoadedModuleList */
    for (NextEntry = PsLoadedModuleList->Flink;
        NextEntry != PsLoadedModuleList;
        NextEntry = NextEntry->Flink)
    {
        LdrEntry = (PLDR_DATA_TABLE_ENTRY)NextEntry;
        if (RtlEqualUnicodeString(&uModuleName, &LdrEntry->BaseDllName, TRUE))
        {
            return LdrEntry->DllBase;
        }
    }
    return NULL;
}

PVOID Utils::GetModuleBaseEx(PCHAR szModuleName, SIZE_T* size)
{
    UNICODE_STRING uName = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    PLIST_ENTRY PsLoadedModuleList, NextEntry;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    UNICODE_STRING uModuleName = { 0 };

    PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&uName);
    if (!MmIsAddressValid(PsLoadedModuleList))
    {
        return NULL;
    }
    RtlCaptureAnsiString(&uModuleName, szModuleName, TRUE);

    /* Lookup the new Ldr entry in PsLoadedModuleList */
    for (NextEntry = PsLoadedModuleList->Flink;
        NextEntry != PsLoadedModuleList;
        NextEntry = NextEntry->Flink)
    {
        LdrEntry = (PLDR_DATA_TABLE_ENTRY)NextEntry;
        if (RtlEqualUnicodeString(&uModuleName, &LdrEntry->BaseDllName, TRUE))
        {
            if (size)
                *size = LdrEntry->SizeOfImage;
            return LdrEntry->DllBase;
        }
    }
    return NULL;
}

PVOID Utils::GetProcAddress(PVOID ModuleBase, PCHAR szFuncName)
{
	return RtlFindExportedRoutineByName(ModuleBase, szFuncName);
}

ULONG Utils::GetActiveProcessLinksOffset()
{
    UNICODE_STRING FunName = { 0 };
    RtlInitUnicodeString(&FunName, skCrypt(L"PsGetProcessId"));

    /*
    .text:000000014007E054                   PsGetProcessId  proc near
    .text:000000014007E054
    .text:000000014007E054 48 8B 81 80 01 00+                mov     rax, [rcx+180h]
    .text:000000014007E054 00
    .text:000000014007E05B C3                                retn
    .text:000000014007E05B                   PsGetProcessId  endp
    */

    PUCHAR pfnPsGetProcessId = (PUCHAR)MmGetSystemRoutineAddress(&FunName);
    if (pfnPsGetProcessId && MmIsAddressValid(pfnPsGetProcessId) && MmIsAddressValid(pfnPsGetProcessId + 0x7))
    {
        for (size_t i = 0; i < 0x7; i++)
        {
            if (pfnPsGetProcessId[i] == 0x48 && pfnPsGetProcessId[i + 1] == 0x8B)
            {
                return *(PULONG)(pfnPsGetProcessId + i + 3) + 8;
            }
        }
    }
    return 0;
}

HANDLE Utils::GetProcessIdByName(PCHAR szName)
{
    PEPROCESS Process = GetProcessByName(szName);
    if (Process)
    {
        return PsGetProcessId(Process);
    }
    return NULL;
}

PEPROCESS Utils::GetProcessByProcessId(HANDLE pid)
{
    PEPROCESS Process = NULL;
	PsLookupProcessByProcessId(pid, &Process);
    if (Process)
	    ObDereferenceObject(Process);
	return Process;
}

PEPROCESS Utils::GetProcessByName(PCHAR szName)
{
    PEPROCESS Process = NULL;
    PCHAR ProcessName = NULL;
    PLIST_ENTRY pHead = NULL;
    PLIST_ENTRY pNode = NULL;

    ULONG64 ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
    //KdPrint(("ActiveProcessLinksOffset = %llX\n", ActiveProcessLinksOffset));
    if (!ActiveProcessLinksOffset)
    {
        KdPrint(("GetActiveProcessLinksOffset failed\n"));
        return NULL;
    }
    Process = PsGetCurrentProcess();

    pHead = (PLIST_ENTRY)((ULONG64)Process + ActiveProcessLinksOffset);
    pNode = pHead;

    do
    {
        Process = (PEPROCESS)((ULONG64)pNode - ActiveProcessLinksOffset);
        ProcessName = PsGetProcessImageFileName(Process);
        //KdPrint(("%s\n", ProcessName));
        if (!strcmp(szName, ProcessName))
        {
            return Process;
        }
        pNode = pNode->Flink;
    } while (pNode != pHead);

    return NULL;
}

PEPROCESS Utils::GetProcessByProcessIdEx(HANDLE pid)
{
	PEPROCESS Process = NULL;
	PLIST_ENTRY pHead = NULL;
	PLIST_ENTRY pNode = NULL;

    static ULONG64 ActiveProcessLinksOffset;
    
	if (!ActiveProcessLinksOffset)
	{
        ActiveProcessLinksOffset = GetActiveProcessLinksOffset();
        if (!ActiveProcessLinksOffset) {
            KdPrint(("GetActiveProcessLinksOffset failed\n"));
            return NULL;
        }
	    //KdPrint(("ActiveProcessLinksOffset = %llX\n", ActiveProcessLinksOffset));
	}
	Process = PsGetCurrentProcess();

	pHead = (PLIST_ENTRY)((ULONG64)Process + ActiveProcessLinksOffset);
	pNode = pHead;

	do {
		Process = (PEPROCESS)((ULONG64)pNode - ActiveProcessLinksOffset);
		if (PsGetProcessId(Process) == pid)
			return Process;
		pNode = pNode->Flink;
	} while (pNode != pHead);

	return NULL;
}

PVOID Utils::GetProcessBaseAddress(HANDLE pid)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return NULL;

	NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NULL;

	PVOID Base = PsGetProcessSectionBaseAddress(pProcess);
	ObDereferenceObject(pProcess);
	return Base;
}

PETHREAD Utils::GetProcessMainThread(PEPROCESS Process)
{
    PETHREAD ethread = NULL;
    KAPC_STATE kApcState = { 0 };
    HANDLE hThread = NULL;

    KeStackAttachProcess(Process, &kApcState);

#pragma warning(disable:6387)
    NTSTATUS status = ZwGetNextThread(NtCurrentProcess(), NULL, THREAD_ALL_ACCESS,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &hThread);

    if (NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS,
            *PsThreadType, KernelMode, (PVOID*)&ethread, NULL);
        NtClose(hThread);

        if (!NT_SUCCESS(status))
        {
            ethread = NULL;
        }
    }
    KeUnstackDetachProcess(&kApcState);
    return ethread;
}

ULONG64 Utils::FindPattern(ULONG64 base, SIZE_T size, PCHAR pattern, PCHAR mask)
{
    const auto patternSize = strlen(mask);

    for (size_t i = 0; i < size - patternSize; i++) {
        for (size_t j = 0; j < patternSize; j++) {
            if (mask[j] != '?' && *reinterpret_cast<PBYTE>(base + i + j) != static_cast<BYTE>(pattern[j]))
                break;

            if (j == patternSize - 1)
                return (ULONG64)base + i;
        }
    }
    return 0;
}

/*
//Only Support ? And Not Support ??
ULONG64 Utils::FindPattern(ULONG64 base, SIZE_T size, PCHAR pattern)
{
    //find pattern utils
    #define InRange(x, a, b) (x >= a && x <= b) 
    #define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
    #define GetByte(x) ((BYTE)(GetBits(x[0]) << 4 | GetBits(x[1])))

    //get module range
    PBYTE ModuleStart = (PBYTE)base;
    PBYTE ModuleEnd = (PBYTE)(ModuleStart + size);

    //scan pattern main
    PBYTE FirstMatch = nullptr;
    const char* CurPatt = pattern;
    for (; ModuleStart < ModuleEnd; ++ModuleStart)
    {
        bool SkipByte = (*CurPatt == '\?');
        if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
            if (!FirstMatch) FirstMatch = ModuleStart;
            SkipByte ? CurPatt += 2 : CurPatt += 3;
            if (CurPatt[-1] == 0) return (ULONG64)FirstMatch;
        }

        else if (FirstMatch) {
            ModuleStart = FirstMatch;
            FirstMatch = nullptr;
            CurPatt = pattern;
        }
    }
    return NULL;
}
*/

ULONG64 Utils::FindPattern(ULONG64 base, SIZE_T size, PCHAR pattern)
{
    #define InRange(x, a, b) (x >= a && x <= b) 
    #define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
    #define GetByte(x) ((BYTE)(GetBits(x[0]) << 4 | GetBits(x[1])))

    const char* CurPatt = pattern;
    uintptr_t FirstMatch = 0;

    if (!base)
        return 0;

    for (uintptr_t current = base; current < base + size; current++)
    {
        if (!*CurPatt)
            return FirstMatch;

        if (*(BYTE*)CurPatt == '\?' || *(BYTE*)current == GetByte(CurPatt))
        {
            if (!FirstMatch)
                FirstMatch = current;
            if (!CurPatt[2])
                return FirstMatch;
            if (*(WORD*)CurPatt == '\?\?' || *(BYTE*)CurPatt != '\?')
                CurPatt += 3;
            else
                CurPatt += 2;
        }
        else
        {
            CurPatt = pattern;
            FirstMatch = 0;
        }
    }
    return 0;
}

ULONG64 Utils::FindPatternImage(PCHAR module, PCHAR section, PCHAR pattern, PCHAR mask)
{
    uintptr_t ModuleBase = 0;
    SIZE_T SectionSize = 0;

    ModuleBase = (uintptr_t)GetModuleBase(module);
    if (!ModuleBase)
        return 0;

    const auto SectionBase = GetImageSectionByName(ModuleBase, section, &SectionSize);
    if (!SectionBase)
        return 0;

    return FindPattern(SectionBase, SectionSize, pattern, mask);
}

ULONG64 Utils::FindPatternImage(PCHAR module, PCHAR section, PCHAR pattern)
{
    uintptr_t ModuleBase = 0;
    SIZE_T SectionSize = 0;

    ModuleBase = (uintptr_t)GetModuleBase(module);
    if (!ModuleBase)
        return 0;

    const auto SectionBase = GetImageSectionByName(ModuleBase, section, &SectionSize);
    if (!SectionBase)
        return 0;

    return FindPattern(SectionBase, SectionSize, pattern);
}


ULONG64 Utils::GetImageSectionByName(ULONG64 imageBase, PCHAR sectionName, SIZE_T* sizeOut)
{
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
        return 0;

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
    const auto sectionCount = ntHeader->FileHeader.NumberOfSections;

    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (size_t i = 0; i < sectionCount; ++i, ++sectionHeader) {
        if (!strcmp(sectionName, reinterpret_cast<const char*>(sectionHeader->Name))) {
            if (sizeOut)
                *sizeOut = sectionHeader->Misc.VirtualSize;
            return imageBase + sectionHeader->VirtualAddress;
        }
    }
    return 0;
}


PSERVICE_DESCRIPTOR_TABLE Utils::GetKeServiceDescriptorTableShadow()
{
    auto keServiceDescriptorTableShadow = FindPatternImage(skCrypt("ntoskrnl.exe"), skCrypt(".text"),
        "\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F", skCrypt("xxxxxxxxx"));
    if (!keServiceDescriptorTableShadow)
        return 0;

    keServiceDescriptorTableShadow += 21;
    keServiceDescriptorTableShadow += *reinterpret_cast<int*>(keServiceDescriptorTableShadow) + sizeof(int);

    return (PSERVICE_DESCRIPTOR_TABLE)keServiceDescriptorTableShadow;
}


PVOID Utils::GetServiceFunctionByIndex(PSYSTEM_SERVICE_TABLE ServiceTable, ULONG ServiceId)
{
    PULONG ServiceTableBase = (PULONG)ServiceTable->ServiceTable;
    if (!MmIsAddressValid(ServiceTableBase))
        return NULL;
    return (PVOID)((ULONG64)(ServiceTableBase) + (ServiceTableBase[ServiceId & 0xFFF] >> 4));
}

VOID Utils::Sleep(ULONG Milliseconds)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -1 * 10000LL * (LONGLONG)Milliseconds;
	KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
}

typedef struct _RegisterCallbackEntry
{
	LIST_ENTRY ListEntryHead;
	BOOLEAN PendingDelete;
	LARGE_INTEGER Cookie;
	void* Context;
	void* Routine;
} RegisterCallbackEntry, * PRegisterCallbackEntry;

NTSTATUS Utils::SafeCmRegisterCallback(PEX_CALLBACK_FUNCTION Function, PVOID Context, PLARGE_INTEGER Cookie)
{
    LARGE_INTEGER LowAddress, HighAddress, SkipBytes;
    LowAddress.QuadPart = 0;
    HighAddress.QuadPart = 0xffffffffffffffffULL;
    SkipBytes.QuadPart = 0;

    auto CmiCallbackHead = (PRegisterCallbackEntry)Offsets::CmCallbackListHead.Address;

    auto mdl = MmAllocatePagesForMdl(LowAddress, HighAddress, SkipBytes, sizeof(RegisterCallbackEntry));
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    auto Mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!Mapping) {
        MmFreePagesFromMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const auto status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        MmUnmapLockedPages(Mapping, mdl);
        MmFreePagesFromMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!Memory::ClearPFN(mdl)) {
        MmUnmapLockedPages(Mapping, mdl);
        MmFreePagesFromMdl(mdl);
        return STATUS_UNSUCCESSFUL;
    }

    auto ListMap = PRegisterCallbackEntry(Mapping);

    //Sometimes trigger BSOD
    UCHAR ShellCode[] = {           //make a jmp
        0x50,															//push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov  rax, 0xffffffffffffffff
        0x48, 0xC1, 0xC8, 0x28,											//ror  rax, 0x48
        0x48, 0x87, 0x04, 0x24,											//xchg qword [rsp], rax
        0xC3															//ret
    };
    auto CodeCave = (PVOID*)Utils::FindPatternImage(skCrypt("pci.sys"), skCrypt(".text"),
        "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
        skCrypt("xxxxxxxxxxxxxxxxxxxxxx"));
    if (!CodeCave) {
        return FALSE;
    }

    *(ULONG64*)(ShellCode + 3) = Utils::__ROL__((ULONG64)Function, 0x28);

    if (!Memory::WriteToReadOnly(PVOID(CodeCave), ShellCode, sizeof(ShellCode))) {
        return STATUS_UNSUCCESSFUL;
    }

	ListMap->Routine = PVOID(CodeCave);
    ListMap->Context = Context;
    ListMap->PendingDelete = FALSE;
	ListMap->Cookie.QuadPart = (ULONG64)ListMap; // put a random number

    //ListMap->Routine = Function;
    //ListMap->Context = Context;
    //ListMap->PendingDelete = FALSE;
    //ListMap->Cookie.QuadPart = (ULONG64)ListMap; // put a random number

    InsertTailList(&CmiCallbackHead->ListEntryHead, &ListMap->ListEntryHead);

    *Cookie = ListMap->Cookie;
    return STATUS_SUCCESS;

	// Do this if you want to delete the callback later when you don't need it
	// RemoveEntryList(&ListMap->ListEntryHead);
}

NTSTATUS Utils::SafeCmUnRegisterCallback(LARGE_INTEGER Cookie)
{
    BYTE Dummy[] = { 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
                     0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
                     0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };

	auto CmiCallbackHead = (PRegisterCallbackEntry)Offsets::CmCallbackListHead.Address;
    PRegisterCallbackEntry CurrentNode = CmiCallbackHead;
    do 
    {
        if (CurrentNode->Cookie.QuadPart == Cookie.QuadPart)
        {
            RemoveEntryList(&CurrentNode->ListEntryHead);
            Memory::WriteToReadOnly(CurrentNode->Routine, Dummy, sizeof(Dummy));
            return STATUS_SUCCESS;
        }
        CurrentNode = (PRegisterCallbackEntry)CurrentNode->ListEntryHead.Flink;
    } while (CurrentNode != CmiCallbackHead);
    return STATUS_UNSUCCESSFUL;
}

PDRIVER_OBJECT Utils::GetDriverObjectByName(PWCHAR DriverName)
{
    NTSTATUS		status;
    UNICODE_STRING	usObjectName;
    UNICODE_STRING	usFileObject;
    PDRIVER_OBJECT	DriverObject = NULL;
    WCHAR			szDriver[MAX_PATH] = L"\\Driver\\";
    WCHAR			szFileSystem[MAX_PATH] = L"\\FileSystem\\";

    wcscat(szDriver, DriverName);
    wcscat(szFileSystem, DriverName);

    RtlInitUnicodeString(&usObjectName, szDriver);
    RtlInitUnicodeString(&usFileObject, szFileSystem);

    // 有些是文件系统 "\\FileSystem\\Ntfs"  https://bbs.kanxue.com/thread-99970.htm
    status = ObReferenceObjectByName(
        &usObjectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&DriverObject);

    if (!NT_SUCCESS(status))
    {
        status = ObReferenceObjectByName(
            &usFileObject,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&DriverObject);

        if (!NT_SUCCESS(status)) {
            return NULL;
        }
    }

    ObDereferenceObject(DriverObject);
    return DriverObject;
}
