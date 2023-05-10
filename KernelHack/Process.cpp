/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Process.hpp"
#include "Imports.h"
#include "Memory.hpp"
#include "Offsets.hpp"
#include "Utils.hpp"


PVOID Process::GetModuleBase(PCHAR ModuleName)
{
	PVOID mBase = 0;
	UNICODE_STRING uModuleName;

	Utils::RtlCaptureAnsiString(&uModuleName, ModuleName, TRUE);
	PPEB pPeb = PsGetProcessPeb(PsGetCurrentProcess());
	
	for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (RtlEqualUnicodeString(&pEntry->BaseDllName, &uModuleName, TRUE)) {
			mBase = pEntry->DllBase;
			break;
		}
	}
	return mBase;
}

PVOID Process::GetModuleBase(PEPROCESS Process, PCHAR ModuleName)
{
	PVOID mBase = 0;
	UNICODE_STRING uModuleName;
	if (!Process)
		return NULL;

	Utils::RtlCaptureAnsiString(&uModuleName, ModuleName, TRUE);
	PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);
	if (pPeb32)
	{
		AttachProcess(Process);
		for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InMemoryOrderModuleList.Flink;
			pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InMemoryOrderModuleList;
			pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

			UNICODE_STRING usCurrentName = { 0 };
			RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);

			if (RtlEqualUnicodeString(&usCurrentName, &uModuleName, TRUE)) {
				mBase = (PVOID)LdrEntry->DllBase;
				break;
			}
		}
		DetachProcess();
		return mBase;
	}
	else
	{
		PPEB pPeb = PsGetProcessPeb(Process);
		AttachProcess(Process);
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
			pListEntry != &pPeb->Ldr->InMemoryOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			//KdPrint(("BaseDllName = %wZ\n", &pEntry->BaseDllName));
			if (RtlEqualUnicodeString(&pEntry->BaseDllName, &uModuleName, TRUE)) {
				mBase = pEntry->DllBase;
				break;
			}
		}
		DetachProcess();
		return mBase;
	}
}

PVOID Process::ProtectProcess(PEPROCESS Process)
{
	UNREFERENCED_PARAMETER(Process);
	return PVOID();
}

PETHREAD Process::GetProcessMainThread(PEPROCESS Process)
{
	PLIST_ENTRY ThreadListHead;
	PLIST_ENTRY ThreadListEntry;
	PETHREAD Thread;
	//Win7 ~ Win11
	ThreadListHead = (PLIST_ENTRY)((ULONG64)Process + 0x30);
	ThreadListEntry = ThreadListHead->Flink;
	Thread = (PETHREAD)((ULONG64)ThreadListEntry - 0x2F8);
	return Thread;
}

KTRAP_FRAME Process::GetThreadTrapFrame(PETHREAD Thread)
{
	return **(PKTRAP_FRAME*)((ULONG64)Thread + 0x90);	//Win10
}

void Process::SetThreadTrapFrame(PETHREAD Thread, KTRAP_FRAME TrapFrame)
{
	**(PKTRAP_FRAME*)((ULONG64)Thread + 0x90) = TrapFrame;
}

BOOLEAN Process::InjectShellcode(PEPROCESS Process, PBYTE Shellcode, SIZE_T Size)
{
	PETHREAD MainThread;
	KTRAP_FRAME TrapFrame;
	PVOID BaseAddress;
	SIZE_T AllocationSize;
	ULONG64 ShellcodeAddress;
	NTSTATUS status;

	typedef ULONG (*pfnKeXXXThread)(PETHREAD Thread);
	pfnKeXXXThread KeSuspendThread = (pfnKeXXXThread)Offsets::KeSuspendThread.Address;
	pfnKeXXXThread KeResumeThread = (pfnKeXXXThread)Offsets::KeResumeThread.Address;
	if (!KeSuspendThread || !KeResumeThread)
		return FALSE;
	MainThread = GetProcessMainThread(Process);
	KeSuspendThread(MainThread);
	TrapFrame = GetThreadTrapFrame(MainThread);

	BYTE ShellcodePacket[] = {
		0x48,0x83,0xEC,0x28,								//sub rsp,28
		0x50,
		0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//mov rax,0xffffffffffffffff
		0xFF,0xD0,											//call rax
		0x58,
		0x48,0x83,0xC4,0x28,								//add rsp,28

		0x50,												//push rax
		0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//mov rax, 0xffffffffffffffff
		0x48,0x87,0x04,0x24,								//xchg qword [rsp], rax
		0xC3												//ret
	};

	BaseAddress = 0;
	AllocationSize = Size + sizeof(ShellcodePacket);
	status = SafeAllocateExecuteMemory(Process, &BaseAddress, &AllocationSize);
	if (!NT_SUCCESS(status) || AllocationSize < Size)
	{
		KeResumeThread(MainThread);
		return FALSE;
	}
	//KdPrint(("BaseAddress = %p\n", BaseAddress));

	ShellcodeAddress = (ULONG64)BaseAddress + sizeof(ShellcodePacket);
	*(PULONG64)(ShellcodePacket + 7) = ShellcodeAddress;
	*(PULONG64)(ShellcodePacket + 25) = TrapFrame.Rip;

	Memory::WriteProcessMemory(Process, BaseAddress, ShellcodePacket, sizeof(ShellcodePacket));
	Memory::WriteProcessMemory(Process, (PVOID)ShellcodeAddress, Shellcode, (ULONG)Size);

	TrapFrame.Rip = (ULONG64)BaseAddress;
	SetThreadTrapFrame(MainThread, TrapFrame);
	KeResumeThread(MainThread);

	//Utils::Sleep(500);
	//FreeVirtualMemory(Process, &BaseAddress, &AllocationSize);
	return TRUE;
}

void
CopyList(IN PLIST_ENTRY Original,
	IN PLIST_ENTRY Copy,
	IN KPROCESSOR_MODE Mode)
{
	if (IsListEmpty(&Original[Mode]))
	{
		InitializeListHead(&Copy[Mode]);
	}
	else
	{
		Copy[Mode].Flink = Original[Mode].Flink;
		Copy[Mode].Blink = Original[Mode].Blink;
		Original[Mode].Flink->Blink = &Copy[Mode];
		Original[Mode].Blink->Flink = &Copy[Mode];
	}
}

void
MoveApcState(PKAPC_STATE OldState,
	PKAPC_STATE NewState)
{
	RtlCopyMemory(NewState, OldState, sizeof(KAPC_STATE));

	CopyList(OldState->ApcListHead, NewState->ApcListHead, KernelMode);
	CopyList(OldState->ApcListHead, NewState->ApcListHead, UserMode);
}

uintptr_t OldProcess;
void Process::AttachProcess(PEPROCESS NewProcess)
{
	PKTHREAD Thread = KeGetCurrentThread();
	PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98); // 0x98 = _KTHREAD::ApcState

	if (*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) == NewProcess) // 0x20 = _KAPC_STATE::Process
		return;

	if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) != 0)) // 0x24a = _KTHREAD::ApcStateIndex
	{
		KeBugCheck(INVALID_PROCESS_ATTACH_ATTEMPT);
		return;
	}

	MoveApcState(ApcState, *(PKAPC_STATE*)(uintptr_t(Thread) + 0x258)); // 0x258 = _KTHREAD::SavedApcState

	InitializeListHead(&ApcState->ApcListHead[KernelMode]);
	InitializeListHead(&ApcState->ApcListHead[UserMode]);

	OldProcess = *(uintptr_t*)(uintptr_t(ApcState) + 0x20);

	*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) = NewProcess; // 0x20 = _KAPC_STATE::Process
	*(UCHAR*)(uintptr_t(ApcState) + 0x28) = 0;				// 0x28 = _KAPC_STATE::InProgressFlags
	*(UCHAR*)(uintptr_t(ApcState) + 0x29) = 0;				// 0x29 = _KAPC_STATE::KernelApcPending
	*(UCHAR*)(uintptr_t(ApcState) + 0x2a) = 0;				// 0x2a = _KAPC_STATE::UserApcPendingAll

	*(UCHAR*)(uintptr_t(Thread) + 0x24a) = 1; // 0x24a = _KTHREAD::ApcStateIndex

	auto DirectoryTableBase = *(uintptr_t*)(uintptr_t(NewProcess) + 0x28);  // 0x28 = _EPROCESS::DirectoryTableBase
	__writecr3(DirectoryTableBase);
}

void Process::DetachProcess()
{
	PKTHREAD Thread = KeGetCurrentThread();
	PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98); // 0x98 = _KTHREAD->ApcState

	if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) == 0)) // 0x24a = KTHREAD->ApcStateIndex
		return;

	if ((*(UCHAR*)(uintptr_t(ApcState) + 0x28)) ||  // 0x28 = _KAPC_STATE->InProgressFlags
		!(IsListEmpty(&ApcState->ApcListHead[KernelMode])) ||
		!(IsListEmpty(&ApcState->ApcListHead[UserMode])))
	{
		KeBugCheck(INVALID_PROCESS_DETACH_ATTEMPT);
	}

	MoveApcState(*(PKAPC_STATE*)(uintptr_t(Thread) + 0x258), ApcState); // 0x258 = _KTHREAD::SavedApcState

	if (OldProcess)
		*(uintptr_t*)(uintptr_t(ApcState) + 0x20) = OldProcess; // 0x20 = _KAPC_STATE::Process

	*(PEPROCESS*)(*(uintptr_t*)(uintptr_t(Thread) + 0x258) + 0x20) = 0; // 0x258 = _KTHREAD::SavedApcState + 0x20 = _KAPC_STATE::Process

	*(UCHAR*)(uintptr_t(Thread) + 0x24a) = 0; // 0x24a = _KTHREAD::ApcStateIndex

	auto DirectoryTableBase = *(uintptr_t*)(uintptr_t(*(PEPROCESS*)(uintptr_t(ApcState) + 0x20)) + 0x28); // 0x20 = _KAPC_STATE::Process + 0x28 = _EPROCESS::DirectoryTableBase
	__writecr3(DirectoryTableBase);

	if (!(IsListEmpty(&ApcState->ApcListHead[KernelMode])))
	{
		*(UCHAR*)(uintptr_t(ApcState) + 0x29) = 1; // 0x29 = _KAPC_STATE::KernelApcPending
	}

	RemoveEntryList(&ApcState->ApcListHead[KernelMode]);
	OldProcess = 0;
}

NTSTATUS Process::ReadVirtualMemory(PEPROCESS Process, PVOID Destination, PVOID Source, SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	BOOLEAN IsAttached;

	// 1. Attach to the process
	//    Sets specified process's PML4 to the CR3
	AttachProcess(Process);
	IsAttached = TRUE;

	if (!MmIsAddressValid(Source))
		goto _Exit;

	// 2. Get the physical address corresponding to the user virtual memory
	SourcePhysicalAddress = Memory::SafeMmGetPhysicalAddress(Source);

	// 3. Detach from the process
	//    Restores previous the current thread
	DetachProcess();
	IsAttached = FALSE;

	if (!SourcePhysicalAddress.QuadPart)
		return ntStatus;

	// 4. Map an IO space for MDL
	MappedIoSpace = MmMapIoSpaceEx(SourcePhysicalAddress, Size, PAGE_READWRITE);
	if (!MappedIoSpace)
		goto _Exit;

	// 5. copy memory
	memcpy(Destination, MappedIoSpace, Size);

	// 6. Free Map
	MmUnmapIoSpace(MappedIoSpace, Size);

	ntStatus = STATUS_SUCCESS;

_Exit:

	if (IsAttached)
		DetachProcess();

	return ntStatus;
}

NTSTATUS Process::WriteVirtualMemory(PEPROCESS Process, PVOID Destination, PVOID Source, SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	BOOLEAN IsAttached;

	// 1. Attach to the process
	  //    Sets specified process's PML4 to the CR3
	AttachProcess(Process);
	IsAttached = TRUE;

	if (!MmIsAddressValid(Source))
		goto _Exit;

	// 2. Get the physical address corresponding to the user virtual memory
	SourcePhysicalAddress = Memory::SafeMmGetPhysicalAddress(Source);

	// 3. Detach from the process
	//    Restores previous the current thread
	DetachProcess();
	IsAttached = FALSE;

	if (!SourcePhysicalAddress.QuadPart)
		return ntStatus;

	// 4. Map an IO space for MDL
	MappedIoSpace = MmMapIoSpaceEx(SourcePhysicalAddress, Size, PAGE_READWRITE);
	if (!MappedIoSpace)
		goto _Exit;

	// 5. copy memory
	memcpy(MappedIoSpace, Destination, Size);

	// 6. Free Map
	MmUnmapIoSpace(MappedIoSpace, Size);

	ntStatus = STATUS_SUCCESS;

_Exit:
	if (IsAttached)
		DetachProcess();
	return ntStatus;
}

NTSTATUS Process::AllocateVirtualMemory(PEPROCESS Process, PVOID* BaseAddress, SIZE_T* Size, DWORD fProtect)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	BOOLEAN IsAttached;

	AttachProcess(Process);
	IsAttached = TRUE;

	ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), BaseAddress, 0, Size, MEM_COMMIT, fProtect);
	if (!NT_SUCCESS(ntStatus))
		goto _Exit;
	memset(*BaseAddress, 0, *Size);
	DetachProcess();
	IsAttached = FALSE;
	ntStatus = STATUS_SUCCESS;
_Exit:
	if (IsAttached)
		DetachProcess();
	return ntStatus;
}

NTSTATUS Process::FreeVirtualMemory(PEPROCESS Process, PVOID* BaseAddress, SIZE_T* Size)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	AttachProcess(Process);
	ntStatus = ZwFreeVirtualMemory(NtCurrentProcess(), BaseAddress, Size, MEM_DECOMMIT);
	DetachProcess();
	return ntStatus;
}

NTSTATUS Process::SafeAllocateExecuteMemory(PEPROCESS Process, PVOID* BaseAddress, SIZE_T* Size)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	BOOLEAN IsAttached;

	AttachProcess(Process);
	IsAttached = TRUE;

	ntStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), BaseAddress, 0, Size, MEM_COMMIT, PAGE_READONLY);
	if (!NT_SUCCESS(ntStatus))
		goto _Exit;

	PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, *Size, 'FKY');
	if (!Buffer)
		goto _Exit;
	memcpy(Buffer, *BaseAddress, *Size);	//读一下PageFault分配物理页
	ExFreePoolWithTag(Buffer, 'FKY');

	//Memory::MmSetPageProtection(*BaseAddress, *Size, PAGE_EXECUTE_READWRITE);
	Memory::SetExecutePage((ULONG64)*BaseAddress, *Size);

	DetachProcess();
	IsAttached = FALSE;
	ntStatus = STATUS_SUCCESS;
_Exit:
	if (IsAttached)
		DetachProcess();
	return ntStatus;
}

