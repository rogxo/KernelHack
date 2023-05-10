/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Mapper.hpp"
#include "Imports.h"
#include "Utils.hpp"
#include "Memory.hpp"


PIMAGE_SECTION_HEADER TranslateRawSection(PIMAGE_NT_HEADERS nt, DWORD rva)
{
	auto section = IMAGE_FIRST_SECTION(nt);
	for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
			return section;
	return NULL;
}

PVOID TranslateRaw(PBYTE base, PIMAGE_NT_HEADERS nt, DWORD rva)
{
	auto section = TranslateRawSection(nt, rva);
	if (!section)
		return NULL;
	return base + section->PointerToRawData + (rva - section->VirtualAddress);
}

BOOLEAN Mapper::ResolveImports(uintptr_t ImageBase)
{
	const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
	const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(ImageBase + dosHeaders->e_lfanew);
	auto rva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!rva)
		return TRUE;

	auto importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)TranslateRaw((PBYTE)ImageBase, ntHeaders, rva);
	if (!importDescriptor)
		return TRUE;

	for (; importDescriptor->FirstThunk; ++importDescriptor)
	{
		auto moduleName = PCHAR(TranslateRaw((PBYTE)ImageBase, ntHeaders, importDescriptor->Name));
		if (!moduleName)
			break;

		uintptr_t processModuleBase = NULL;
		size_t processModuleSize = 0;

		processModuleBase = (uintptr_t)Utils::GetModuleBase(moduleName, &processModuleSize);
		if (!processModuleBase)
			return FALSE;

		//缺陷：只能处理ntoskrnl的导入函数，实测导入HAL.dll!KeQueryPerformanceCounter失败
		for (auto thunk = PIMAGE_THUNK_DATA(TranslateRaw((PBYTE)ImageBase, ntHeaders, importDescriptor->FirstThunk)); thunk->u1.AddressOfData; ++thunk)
		{
			auto importByName = (PIMAGE_IMPORT_BY_NAME)TranslateRaw((PBYTE)ImageBase, ntHeaders, static_cast<DWORD>(thunk->u1.AddressOfData));
			uintptr_t funcPtr = (uintptr_t)RtlFindExportedRoutineByName((PVOID)processModuleBase, importByName->Name);
			if (!funcPtr)
				return FALSE;

			thunk->u1.Function = funcPtr;
		}
	}
	return TRUE;
}

void Mapper::ResolveRelocations(uintptr_t imageBase, uintptr_t newBase, uintptr_t delta)
{
	const auto dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	const auto ntHeaders = (PIMAGE_NT_HEADERS64)(imageBase + dosHeaders->e_lfanew);

	DWORD reloc_va = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (!reloc_va)
		return;

	auto current_base_relocation = PIMAGE_BASE_RELOCATION(newBase + reloc_va);
	const auto reloc_end = (ULONG64)current_base_relocation + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	while (current_base_relocation->VirtualAddress && current_base_relocation->VirtualAddress < reloc_end && current_base_relocation->SizeOfBlock)
	{
		ULONG64 current_reloc_address = newBase + current_base_relocation->VirtualAddress;
		PWORD current_reloc_item = PWORD(ULONG64(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
		ULONG current_reloc_count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(PWORD);

		for (auto i = 0u; i < current_reloc_count; ++i)
		{
			const WORD type = current_reloc_item[i] >> 12;
			const WORD offset = current_reloc_item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc_address + offset) += delta;
		}
		current_base_relocation = PIMAGE_BASE_RELOCATION(ULONG64(current_base_relocation) + current_base_relocation->SizeOfBlock);
	}
}

NTSTATUS Mapper::MapDriver(PVOID data, SIZE_T size)
{
	PUCHAR driverBase = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'CCAV');
	if (!driverBase)
		return STATUS_UNSUCCESSFUL;

	memcpy(driverBase, data, size);
	ResolveImports((uintptr_t)driverBase);

	const auto dosHeaders = (PIMAGE_DOS_HEADER)driverBase;
	const auto ntHeaders = (PIMAGE_NT_HEADERS)(driverBase + dosHeaders->e_lfanew);

	const PIMAGE_SECTION_HEADER currentImageSection = IMAGE_FIRST_SECTION(ntHeaders);

	// Allocate Memory for Mapped Driver w/o HEADERS Size - PAGE_SIZE (Mapping Without PE Header (First Page))
	PUCHAR driverAllocationBase = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, ntHeaders->OptionalHeader.SizeOfImage,'CCAV') - PAGE_SIZE;
	if (!driverAllocationBase)
		return STATUS_UNSUCCESSFUL;

	Memory::CleanBigPoolAllocation(driverAllocationBase + PAGE_SIZE);

	for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		auto sectionAddress = driverAllocationBase + currentImageSection[i].VirtualAddress;
		memcpy(sectionAddress, driverBase + currentImageSection[i].PointerToRawData, currentImageSection[i].SizeOfRawData);
	}

	ResolveRelocations((uintptr_t)driverBase, (uintptr_t)driverAllocationBase, 
		uintptr_t(driverAllocationBase - ntHeaders->OptionalHeader.ImageBase));
	ExFreePool(driverBase);

	HANDLE threadHandle = NULL;
	if (!NT_SUCCESS(PsCreateSystemThread(&threadHandle, NULL, NULL, NULL, NULL,
		(PKSTART_ROUTINE)(driverAllocationBase + ntHeaders->OptionalHeader.AddressOfEntryPoint)
		, NULL)))
		return STATUS_UNSUCCESSFUL;

	ZwClose(threadHandle);
	return STATUS_SUCCESS;
}

NTSTATUS Mapper::MapDriverFromFile(PUNICODE_STRING FilePath)
{
	HANDLE hFile = NULL;
	NTSTATUS status = 0;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	InitializeObjectAttributes(
		&ObjectAttributes,
		FilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(
		&hFile,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status))
		return status;

	FILE_STANDARD_INFORMATION fsi = { 0 };
	status = ZwQueryInformationFile(hFile, &IoStatusBlock, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}

	SIZE_T FileSize = fsi.EndOfFile.QuadPart;
	PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, FileSize, 'CCXV');
	if (!Buffer)
	{
		ZwClose(hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, (ULONG)FileSize, 0, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	ZwClose(hFile);

	status = Mapper::MapDriver(Buffer, FileSize);

	ExFreePoolWithTag(Buffer, 'CCXV');
	return status;
}
