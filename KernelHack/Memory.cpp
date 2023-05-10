/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Memory.hpp"
#include "Utils.hpp"
//#include "miamd.h"
//#include "fastmemcpy.h"
#include "Offsets.hpp"

ULONG64 PTE_BASE;
ULONG64 PDE_BASE;
ULONG64 PPE_BASE;
ULONG64 PXE_BASE;

#define PTE_SHIFT 3
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_PER_PAGE 512    //0x200
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define MiGetPxeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))
#define MiGetPpeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PPI_SHIFT) & PPI_MASK))
#define MiGetPdeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PDI_SHIFT) & (PDI_MASK_AMD64)))
#define MiGetPteOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PTI_SHIFT) & (PTI_MASK_AMD64)))

VOID Memory::InitializePageBase()
{
    ULONG64 dirbase = __readcr3();
	PHYSICAL_ADDRESS phAddr = { 0 };
	ULONG64 slot = 0;
	ULONG_PTR pfn = dirbase >> 12;

	phAddr.QuadPart = pfn << PAGE_SHIFT;

	PHARDWARE_PTE pml4 = (PHARDWARE_PTE)MmGetVirtualForPhysical(phAddr);

	while (pml4[slot].PageFrameNumber != pfn) slot++;

	PTE_BASE = (slot << 39) + 0xFFFF000000000000;
	PDE_BASE = PTE_BASE + (slot << 30);
	PPE_BASE = PDE_BASE + (slot << 21);
	PXE_BASE = PPE_BASE + (slot << 12);

	return;
}

PMMPTE Memory::GetPxeAddress(ULONG64 va)
{
	return ((PMMPTE)PXE_BASE + MiGetPxeOffset(va));
}

PMMPTE Memory::GetPpeAddress(ULONG64 va)
{
	return ((PMMPTE)(((((ULONG_PTR)(va)&VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + PPE_BASE));
}

PMMPTE Memory::GetPdeAddress(ULONG64 va)
{
	return ((PMMPTE)(((((ULONG_PTR)(va)&VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE));
}

PMMPTE Memory::GetPteAddress(ULONG64 va)
{
	return ((PMMPTE)(((((ULONG_PTR)(va)&VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE));
}

NTSTATUS Memory::ReadPhysicalMemory(
    PHYSICAL_ADDRESS TargetAddress,
    PVOID lpBuffer,
    SIZE_T Size)
{
    MM_COPY_ADDRESS AddrToRead = { 0 };
    SIZE_T BytesRead = 0;
    AddrToRead.PhysicalAddress = TargetAddress;
    return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, &BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS Memory::WritePhysicalMemory(
    PHYSICAL_ADDRESS TargetAddress,
    PVOID lpBuffer,
    SIZE_T Size)
{
    PVOID MappedMemory = MmMapIoSpaceEx(TargetAddress, Size, PAGE_READWRITE);
    if (!MappedMemory)
        return STATUS_UNSUCCESSFUL;

    memcpy(MappedMemory, lpBuffer, Size);
    //__movsb((PUCHAR)pmapped_mem, (PUCHAR)lpBuffer, Size);
    MmUnmapIoSpace(MappedMemory, Size);
    return STATUS_SUCCESS;
}

PHYSICAL_ADDRESS Memory::TranslateLinearAddress(
    ULONG64 Dirbase, 
    ULONG64 VirtualAddress)
{
    PHYSICAL_ADDRESS PhysicalAddress = { 0 };
    PHYSICAL_ADDRESS PML4EAddress;
    PHYSICAL_ADDRESS PDPTEAddress;
    PHYSICAL_ADDRESS PDEAddress;
    PHYSICAL_ADDRESS PTEAddress;
    ULONG64 PML4TBase = { 0 };
    ULONG64 PDPTBase = { 0 };
    ULONG64 PDBase = { 0 };
    ULONG64 PTBase = { 0 };
    HARDWARE_PTE PML4E = { 0 };
    HARDWARE_PTE PDPTE = { 0 };
    HARDWARE_PTE PDE = { 0 };
    HARDWARE_PTE PTE = { 0 };
    //9-9-9-9-12
    ULONG64 Pxi = MiGetPxeOffset(VirtualAddress);
    ULONG64 Ppi = MiGetPpeOffset(VirtualAddress);
    ULONG64 Pdi = MiGetPdeOffset(VirtualAddress);
    ULONG64 Pti = MiGetPteOffset(VirtualAddress);

    PML4TBase = Dirbase & ~0xFFF;
    PML4EAddress.QuadPart = PML4TBase + Pxi * 8;
    ReadPhysicalMemory(PML4EAddress, &PML4E, sizeof(PML4E));
    if (!PML4E.Valid) //Present
        return { 0 };

    PDPTBase = PML4E.PageFrameNumber << 12;
    PDPTEAddress.QuadPart = PDPTBase + Ppi * 8;
    ReadPhysicalMemory(PDPTEAddress, &PDPTE, sizeof(PDPTE));
    if (!PDPTE.Valid)
        return { 0 };

    if (PDPTE.LargePage) //1GB Page
    {
        PhysicalAddress.QuadPart = (PDPTE.PageFrameNumber << 12) + (VirtualAddress & ~(~0ull << 30));
        return PhysicalAddress;
    }

    PDBase = PDPTE.PageFrameNumber << 12;
    PDEAddress.QuadPart = PDBase + Pdi * 8;
    ReadPhysicalMemory(PDEAddress, &PDE, sizeof(PDE));
    if (!PDE.Valid)
        return { 0 };

    if (PDE.LargePage)  //2MB Page
    {
        PhysicalAddress.QuadPart = (PDE.PageFrameNumber << 12) + (VirtualAddress & ~(~0ull << 21));
        return PhysicalAddress;
    }

    PTBase = PDE.PageFrameNumber << 12;
    PTEAddress.QuadPart = PTBase + Pti * 8;
    ReadPhysicalMemory(PTEAddress, &PTE, sizeof(PTE));
    if (!PTE.Valid)
        return { 0 };

    PhysicalAddress.QuadPart = (PTE.PageFrameNumber << 12) + (VirtualAddress & 0xFFF);
    return PhysicalAddress;
}

NTSTATUS Memory::ReadVirtualMemory(
    ULONG64 Dirbase,
    PVOID VirtualAddress, 
    PVOID Buffer, 
    SIZE_T Size)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress = TranslateLinearAddress(Dirbase, (ULONG64)VirtualAddress);
    return ReadPhysicalMemory(PhysicalAddress, Buffer, Size);
}

NTSTATUS Memory::WriteVirtualMemory(
    ULONG64 Dirbase, 
    PVOID VirtualAddress, 
    PVOID Buffer, 
    SIZE_T Size)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress = TranslateLinearAddress(Dirbase, (ULONG64)VirtualAddress);
    return WritePhysicalMemory(PhysicalAddress, Buffer, Size);
}

ULONG64 Memory::GetProcessDirbase(PEPROCESS Process)
{
    ULONG64 DirectoryTableBaseOffset = *(PULONG_PTR)((PUCHAR)Process + 0x28);
    /*
    //KPTI
    if (DirectoryTableBaseOffset == 0)
    {
        DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
        ULONG64 UserDirectoryTableBase = *(PULONG_PTR)((PUCHAR)Process + UserDirOffset);
        return UserDirectoryTableBase;
    }
    */
    return DirectoryTableBaseOffset;
}

NTSTATUS Memory::ReadProcessMemory(
    PEPROCESS Process, 
    PVOID VirtualAddress,
    PVOID lpBuffer, 
    SIZE_T Size)
{
    return ReadVirtualMemory(GetProcessDirbase(Process), VirtualAddress, lpBuffer, Size);
}

NTSTATUS Memory::WriteProcessMemory(
    PEPROCESS Process, 
    PVOID VirtualAddress, 
    PVOID lpBuffer, 
    SIZE_T Size)
{
    return WriteVirtualMemory(GetProcessDirbase(Process), VirtualAddress, lpBuffer, Size);
}

NTSTATUS Memory::MmAllocateCopyRemove(
    PVOID SrcPtr,
    ULONG DataSize,
    PPHYSICAL_ADDRESS PhysPtr)
{
    LARGE_INTEGER AllocSize;
    PHYSICAL_ADDRESS MaxPhys;

    PVOID Alloc = NULL;
    MaxPhys.QuadPart = MAXLONG64;
    AllocSize.QuadPart = DataSize;

    Alloc = MmAllocateContiguousMemory(DataSize, MaxPhys);
    if (!Alloc)
        return STATUS_FAIL_CHECK;

    memcpy(Alloc, SrcPtr, DataSize);
    *PhysPtr = SafeMmGetPhysicalAddress(Alloc);

    MmFreeContiguousMemory(Alloc);
    return MmRemovePhysicalMemory(PhysPtr, &AllocSize);
}

PVOID Memory::AllocateMemoryInSystemSpace(SIZE_T Size)
{
    typedef NTSTATUS(__fastcall*pfnMmCreateSection)(
        _Out_ PVOID* SectionObject,
        _In_ ACCESS_MASK 	DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES 	ObjectAttributes,
        _In_ PLARGE_INTEGER 	MaximumSize,
        _In_ ULONG 	SectionPageProtection,
        _In_ ULONG 	AllocationAttributes,
        _In_opt_ HANDLE 	FileHandle,
        _In_opt_ PFILE_OBJECT 	File
    );
    pfnMmCreateSection MmCreateSection;
    UNICODE_STRING FuncName;

    RtlInitUnicodeString(&FuncName, L"MmCreateSection");
    MmCreateSection = (pfnMmCreateSection)MmGetSystemRoutineAddress(&FuncName);
    if (!MmCreateSection)
        return NULL;

    UNREFERENCED_PARAMETER(Size);
    //MmCreateSection

    //MmMapViewInSystemSpace();
    return PVOID();
}

PVOID Memory::MmAllocateIndependentPages(SIZE_T NumberOfBytes, ULONG Node)
{
    UNREFERENCED_PARAMETER(NumberOfBytes);
    UNREFERENCED_PARAMETER(Node);
    return PVOID();
}

BOOLEAN Memory::ClearPFN(PMDL mdl)
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages)
		return FALSE;

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		SIZE_T bytes = 0;
		MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}
	return TRUE;
}

BOOLEAN Memory::MmSetPageProtection(PVOID VirtualAddress, SIZE_T NumberOfBytes, ULONG NewProtect)
{
    typedef BOOLEAN(__fastcall* pfnMmSetPageProtection)(PVOID VirtualAddress, SIZE_T NumberOfBytes,ULONG NewProtect);
    pfnMmSetPageProtection MmSetPageProtection;
    if (!VirtualAddress || !MmIsAddressValid(VirtualAddress))
        return FALSE;
    MmSetPageProtection = (pfnMmSetPageProtection)Offsets::MmSetPageProtection.Address;
    if (!MmSetPageProtection)
        return FALSE;
    return MmSetPageProtection(VirtualAddress, NumberOfBytes, NewProtect);
}

PHYSICAL_ADDRESS Memory::SafeMmGetPhysicalAddress(PVOID BaseAddress)
{
	static BOOLEAN* KdEnteredDebugger = 0;
	if (!KdEnteredDebugger)
	{
		UNICODE_STRING uVarName = RTL_CONSTANT_STRING(L"KdEnteredDebugger");
		KdEnteredDebugger = (BOOLEAN*)MmGetSystemRoutineAddress(&uVarName);
	}

	*KdEnteredDebugger = FALSE;
	PHYSICAL_ADDRESS PhysicalAddress = MmGetPhysicalAddress(BaseAddress);
	*KdEnteredDebugger = TRUE;

	return PhysicalAddress;
}

typedef struct _PiDDBCacheEntry
{
    LIST_ENTRY		list;
    UNICODE_STRING	driverName;
    ULONG			driverStamp;
    NTSTATUS		loadStatus;
}PiDDBCacheEntry;

typedef struct _POOL_TRACKER_BIG_PAGES
{
	PVOID Va;
	ULONG Key;
	ULONG PoolType;
	ULONG NumberOfBytes;
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

NTSTATUS Memory::CleanPiDDBCache(PDRIVER_OBJECT DriverObject)
{
    uintptr_t piddbLockAddress = Offsets::PiDDBLock.Address;
    uintptr_t piddbTableAddress = Offsets::PiDDBCacheTable.Address;

	PiDDBCacheEntry cacheEntry;
	RtlInitUnicodeString(&cacheEntry.driverName, PKLDR_DATA_TABLE_ENTRY(DriverObject->DriverSection)->BaseDllName.Buffer);

	if (!ExAcquireResourceExclusiveLite(reinterpret_cast<PERESOURCE>(piddbLockAddress), true))
		return STATUS_UNSUCCESSFUL;

	PiDDBCacheEntry* entryPointer =
		reinterpret_cast<PiDDBCacheEntry*>(RtlLookupElementGenericTableAvl(
			reinterpret_cast<PRTL_AVL_TABLE>(piddbTableAddress),
			reinterpret_cast<void*>(&cacheEntry)
		));

	if (entryPointer)
	{
		PLIST_ENTRY NextEntry = entryPointer->list.Flink;
		PLIST_ENTRY PrevEntry = entryPointer->list.Blink;

		PrevEntry->Flink = entryPointer->list.Flink;
		NextEntry->Blink = entryPointer->list.Blink;

		entryPointer->list.Blink = PrevEntry;
		entryPointer->list.Flink = NextEntry;

		RtlDeleteElementGenericTableAvl(reinterpret_cast<PRTL_AVL_TABLE>(piddbTableAddress), entryPointer);
	}
	else
		return STATUS_UNSUCCESSFUL;

	ExReleaseResourceLite(reinterpret_cast<PERESOURCE>(piddbLockAddress));

	return STATUS_SUCCESS;
}

NTSTATUS Memory::CleanBigPoolAllocation(PVOID AllocationAddress)
{
    uintptr_t pPoolBigPageTable = 0;
    uintptr_t pPoolBigPageTableSize = 0;

    pPoolBigPageTable = Offsets::PoolBigPageTable.Address;
    pPoolBigPageTableSize = Offsets::PoolBigPageTable.Address - 0x8;

    PPOOL_TRACKER_BIG_PAGES PoolBigPageTable = 0;
	RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);

	SIZE_T PoolBigPageTableSize = 0;
	RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);

	if (!PoolBigPageTableSize || !PoolBigPageTable)
		return STATUS_NOT_FOUND;

	for (int i = 0; i < PoolBigPageTableSize; i++)
	{
		if (PoolBigPageTable[i].Va == AllocationAddress
            || PoolBigPageTable[i].Va == (PUCHAR)AllocationAddress + 0x1)
		{
            PoolBigPageTable[i].Va = (PVOID)0x1;
			PoolBigPageTable[i].NumberOfBytes = 0x0;

			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}

BOOLEAN Memory::WriteToReadOnly(PVOID destination, PVOID buffer, ULONG size)
{
	PMDL mdl = IoAllocateMdl(destination, size, FALSE, FALSE, 0);
	if (!mdl)
		return FALSE;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);

	auto mmMap = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	memcpy(mmMap, buffer, size);

	MmUnmapLockedPages(mmMap, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

BOOLEAN Memory::SetExecutePage(ULONG64 VirtualAddress, SIZE_T size)
{
	ULONG64 startAddress = VirtualAddress & (~0xFFF); // 起始地址
	ULONG64 endAddress = (VirtualAddress + size) & (~0xFFF); // 结束地址 

    InitializePageBase();

	for (ULONG64 curAddress = startAddress; curAddress <= endAddress; curAddress += PAGE_SIZE)
	{
		PHARDWARE_PTE pde = (PHARDWARE_PTE)GetPdeAddress(curAddress);
		if (MmIsAddressValid(pde) && pde->Valid == 1)
		{
			pde->NoExecute = 0;
			pde->Write = 1;
			//pde->Dirty = 0;
		}

		PHARDWARE_PTE pte = (PHARDWARE_PTE)GetPteAddress(curAddress);
		if (MmIsAddressValid(pte) && pte->Valid == 1)
		{
			pte->NoExecute = 0;
			pte->Write = 1;
			//pte->Dirty = 0;
		}
	}
	return TRUE;
}

/*
NTSTATUS Memory::AllocateInDiscardedMemory(IN ULONG size, OUT PVOID* ppFoundBase)
{
	ASSERT(ppFoundBase != NULL);
	if (ppFoundBase == NULL)
		return STATUS_INVALID_PARAMETER;

	// Ensure MiAllocateDriverPage address is valid
	if (dynData.MiAllocPage == 0)
		return STATUS_INVALID_ADDRESS;

	PVOID pBase = GetKernelBase(NULL);
	fnMiAllocateDriverPage MiAllocateDriverPage = (fnMiAllocateDriverPage)((ULONG_PTR)pBase + dynData.MiAllocPage);

	PIMAGE_NT_HEADERS pNTOSHdr = RtlImageNtHeader(pBase);
	if (!pNTOSHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	// Walk ntoskrnl section
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pNTOSHdr + 1);
	PIMAGE_SECTION_HEADER pLastSection = pFirstSection + pNTOSHdr->FileHeader.NumberOfSections;

	for (PIMAGE_SECTION_HEADER pSection = pLastSection - 1; pSection >= pFirstSection; --pSection)
	{
		// Find first suitable discarded section
		if (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE && (ULONG_PTR)PAGE_ALIGN(pSection->Misc.VirtualSize) >= size)
		{
			// TODO: implement some randomization for starting address
			PVOID pSectionBase = (PUCHAR)pBase + pSection->VirtualAddress;

			// I don't care about large pages
			// If image was mapped using large pages bugcheck is imminent
			ULONG_PTR TotalPTEs = BYTES_TO_PAGES(size);
			PMMPTE pStartPTE = GetPteAddress(pSectionBase);
			PMMPTE pEndPTE = pStartPTE + TotalPTEs;
			MMPTE TempPTE = ValidKernelPte;

			// Allocate physical pages for PTEs
			for (PMMPTE pPTE = pStartPTE; pPTE < pEndPTE; ++pPTE)
			{
				PVOID VA = MiGetVirtualAddressMappedByPte(pPTE);

				// Already allocated
				if (MI_IS_PHYSICAL_ADDRESS(VA))
				{
					//DPRINT( "BlackBone: %s: VA 0x%p is already backed by PFN: 0x%p\n", __FUNCTION__, VA, pPTE->u.Hard.PageFrameNumber );
					continue;
				}

				PFN_NUMBER pfn = MiAllocateDriverPage(pPTE);
				if (pfn == 0)
				{
					KdPrint(("BlackBone: %s: Failed to allocate physical page for PTE 0x%p\n", __FUNCTION__, pPTE));
					return STATUS_NO_MEMORY;
				}
				else
				{
					//DPRINT( "BlackBone: %s: VA 0x%p now backed by PFN: 0x%p; PTE: 0x%p\n", __FUNCTION__, VA, pfn, pPTE );
					TempPTE.u.Hard.PageFrameNumber = pfn;
					*pPTE = TempPTE;
				}
			}

			*ppFoundBase = pSectionBase;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}
*/
