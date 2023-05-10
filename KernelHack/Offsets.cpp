/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Offsets.hpp"
#include "Utils.hpp"
#include "hde/hde.h"
#include "skCrypter.h"

namespace Offsets
{
	OFFSETINFO CmCallbackListHead;
	OFFSETINFO PoolBigPageTable;
	OFFSETINFO PiDDBLock;
	OFFSETINFO PiDDBCacheTable;
	OFFSETINFO KeSuspendThread;
	OFFSETINFO KeResumeThread;
	OFFSETINFO PspNotifyEnableMask;
	OFFSETINFO MmSetPageProtection;
	OFFSETINFO I8xWriteDataToKeyboardQueue;
}

BOOLEAN Offsets::UpdateOffsetInfo(POFFSETINFO OffsetInfo)
{
	ULONG64 found = 0;

	if (OffsetInfo->Mask)
	{
		found = Utils::FindPatternImage(
			OffsetInfo->Module,
			OffsetInfo->Section,
			OffsetInfo->Pattern,
			OffsetInfo->Mask) + OffsetInfo->Offset;	//OPCODE of call/mov/...
	}
	else
	{
		found = Utils::FindPatternImage(
			OffsetInfo->Module,
			OffsetInfo->Section,
			OffsetInfo->Pattern) + OffsetInfo->Offset;
	}
	//KdPrint(("found = %llX\n", found));
	if (found == OffsetInfo->Offset)
		return FALSE;

	hde64s dasm;
	if (hde64_disasm((PVOID)found, &dasm) < 4)
		return FALSE;

	OffsetInfo->Address = *(PLONG)(found + dasm.len - 4) + (found + dasm.len);
	return TRUE;
}

BOOLEAN Offsets::Initialize()
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);
	//DbgPrint("%d\n", verInfo.dwBuildNumber);	//19044

	//7600  0
	//7601  0
	//9200  0
	//9600  0
	//10240 1
	//10586 1
	//14393 1
	//15063 1
	//16299 1
	//17134 1
	//17763 1
	//18362 1
	//18363 1
	//19041 1
	//19042 1
	//19043 1
	//19044 1
	//22000 1
	//22621 1
	//22622	0
	//22623	0
	//25217	0
	//25267	0
	//25276	0
	//25300	0
	//25330	0

	//General Pattern
	if (verInfo.dwBuildNumber >= 10240)
	{
		CmCallbackListHead.Module = skCrypt("ntoskrnl.exe");
		CmCallbackListHead.Section = skCrypt("PAGE");
		CmCallbackListHead.InFunction = skCrypt("CmUnRegisterCallback");
		CmCallbackListHead.Pattern = skCrypt("48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B F8 48 89 44 24 ? 48 85 C0");	//Win10-Win11
		CmCallbackListHead.Mask = 0;
		CmCallbackListHead.Offset = 0x0;

		PiDDBLock.Module = skCrypt("ntoskrnl.exe");
		PiDDBLock.Section = skCrypt("PAGE");
		PiDDBLock.InFunction = skCrypt("PpCheckInDriverDatabase");
		PiDDBLock.Pattern = skCrypt("B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 8C 24");	//10240-19044
		PiDDBLock.Mask = 0;
		PiDDBLock.Offset = 0x2;

		PiDDBCacheTable.Module = skCrypt("ntoskrnl.exe");
		PiDDBCacheTable.Section = skCrypt("PAGE");
		PiDDBCacheTable.InFunction = skCrypt("PiUpdateDriverDBCache");
		PiDDBCacheTable.Pattern = skCrypt("48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 1D ? ? ? ? 48 85 C0 0F");	//Win10-Win11
		PiDDBCacheTable.Mask = 0;
		PiDDBCacheTable.Offset = 0x0;

		KeSuspendThread.Module = skCrypt("ntoskrnl.exe");
		KeSuspendThread.Section = skCrypt("PAGE");
		KeSuspendThread.InFunction = skCrypt("PsSuspendThread");
		KeSuspendThread.Pattern = skCrypt("A8 01 0F 85 ? ? ? ? 48 8B ? E8 ? ? ? ? 89 44 24");	//Win7,Win10-Win11
		KeSuspendThread.Mask = 0;
		KeSuspendThread.Offset = 0xB;

		PspNotifyEnableMask.Module = skCrypt("ntoskrnl.exe");
		PspNotifyEnableMask.Section = skCrypt("PAGE");
		PspNotifyEnableMask.InFunction = skCrypt("PsSetLoadImageNotifyRoutineEx");
		PspNotifyEnableMask.Pattern = skCrypt("8B 05 ? ? ? ? A8 01 75 09 F0 0F BA 2D");		//Win7,Win10-Win11
		PspNotifyEnableMask.Mask = 0;
		PspNotifyEnableMask.Offset = 0x0;

		MmSetPageProtection.Module = skCrypt("ntoskrnl.exe");
		MmSetPageProtection.Section = skCrypt("PAGE");
		MmSetPageProtection.InFunction = skCrypt("MmAllocateIsrStack");
		MmSetPageProtection.Pattern = skCrypt("41 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 ?? 48 81 EB ?? ?? ?? ?? EB");
		MmSetPageProtection.Mask = 0;
		MmSetPageProtection.Offset = 0xC;

		I8xWriteDataToKeyboardQueue.Module = skCrypt("i8042prt.sys");
		I8xWriteDataToKeyboardQueue.Section = skCrypt(".text");
		I8xWriteDataToKeyboardQueue.InFunction = skCrypt("I8xQueueCurrentKeyboardInput");
		I8xWriteDataToKeyboardQueue.Pattern = skCrypt("39 73 ?? 0F ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 84 C0 75 ??");
		I8xWriteDataToKeyboardQueue.Mask = 0;
		I8xWriteDataToKeyboardQueue.Offset = 0x13;
	}

	//PoolBigPageTable
	if (verInfo.dwBuildNumber >= 10240 && verInfo.dwBuildNumber < 19041)
	{
		PoolBigPageTable.Module = skCrypt("ntoskrnl.exe");
		PoolBigPageTable.Section = skCrypt(".text");
		PoolBigPageTable.InFunction = skCrypt("ExGetBigPoolInfo");
		PoolBigPageTable.Pattern = skCrypt("83 ? 01 75 10 48 8B 15 ? ? ? ? 48 8B ? ? ? ? ? EB ? 48");
		PoolBigPageTable.Mask = 0;
		PoolBigPageTable.Offset = 0x5;
	}
	else if (verInfo.dwBuildNumber >= 19041)
	{
		PoolBigPageTable.Module = skCrypt("ntoskrnl.exe");
		PoolBigPageTable.Section = skCrypt(".text");
		PoolBigPageTable.InFunction = skCrypt("ExProtectPoolEx");
		PoolBigPageTable.Pattern = skCrypt("48 C1 E8 ?? 48 33 D8 E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 0F B6 F8");
		PoolBigPageTable.Mask = 0;
		PoolBigPageTable.Offset = 0x13;
	}

	//PiDDBLock
	if (verInfo.dwBuildNumber > 19044 && verInfo.dwBuildNumber < 22621)
	{
		PiDDBLock.Module = skCrypt("ntoskrnl.exe");
		PiDDBLock.Section = skCrypt("PAGE");
		PiDDBLock.InFunction = skCrypt("PpCheckInDriverDatabase");
		PiDDBLock.Pattern = skCrypt("B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 4C 24");
		PiDDBLock.Mask = 0;
		PiDDBLock.Offset = 0x2;
	}
	else if (verInfo.dwBuildNumber >= 22621)
	{
		PiDDBLock.Module = skCrypt("ntoskrnl.exe");
		PiDDBLock.Section = skCrypt("PAGE");
		PiDDBLock.InFunction = skCrypt("PpReleaseBootDDB");
		PiDDBLock.Pattern = skCrypt("48 8D 0D ?? ?? ?? ?? B2 01 66 FF 88 ?? ?? ?? ?? 90 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 85 C9");
		PiDDBLock.Mask = 0;
		PiDDBLock.Offset = 0x0;
	}

	//KeResumeThread
	if (verInfo.dwBuildNumber >= 10240 && verInfo.dwBuildNumber < 14393)
	{

	}
	else if (verInfo.dwBuildNumber >= 14393 && verInfo.dwBuildNumber < 18362)
	{
		KeResumeThread.Module = skCrypt("ntoskrnl.exe");
		KeResumeThread.Section = skCrypt("PAGE");
		KeResumeThread.InFunction = skCrypt("PsResumeProcess");
		KeResumeThread.Pattern = skCrypt("48 8B ? E8 ? ? ? ? 48 8B ? 48 8B ? E8 ? ? ? ? EB ? BB ? ? ? ? EB");
		KeResumeThread.Mask = 0;
		KeResumeThread.Offset = 0x3;
	}
	else if (verInfo.dwBuildNumber >= 18362 && verInfo.dwBuildNumber < 22000)
	{
		KeResumeThread.Module = skCrypt("ntoskrnl.exe");
		KeResumeThread.Section = skCrypt("PAGE");
		KeResumeThread.InFunction = skCrypt("PsResumeProcess");
		KeResumeThread.Pattern = skCrypt("48 8B C8 E8 ? ? ? ? 48 8B D7 48 8B CE");
		KeResumeThread.Mask = 0;
		KeResumeThread.Offset = 0x3;
	}
	else if (verInfo.dwBuildNumber >= 22000)
	{
		KeResumeThread.Module = skCrypt("ntoskrnl.exe");
		KeResumeThread.Section = skCrypt(".text");
		KeResumeThread.InFunction = skCrypt("PsResumeProcess");
		KeResumeThread.Pattern = skCrypt("48 8B C8 E8 ? ? ? ? 48 8B D7 48 8B CE");
		KeResumeThread.Mask = 0;
		KeResumeThread.Offset = 0x3;
	}

	UpdateOffsetInfo(&CmCallbackListHead);
	KdPrint(("CmCallbackListHead = %llX\n", CmCallbackListHead.Address));

	UpdateOffsetInfo(&PiDDBLock);
	KdPrint(("PiDDBLock = %llX\n", PiDDBLock.Address));

	UpdateOffsetInfo(&PiDDBCacheTable);
	KdPrint(("PiDDBCacheTable = %llX\n", PiDDBCacheTable.Address));

	UpdateOffsetInfo(&PoolBigPageTable);
	KdPrint(("PoolBigPageTable = %llX\n", PoolBigPageTable.Address));

	UpdateOffsetInfo(&KeSuspendThread);
	KdPrint(("KeSuspendThread = %llX\n", KeSuspendThread.Address));

	UpdateOffsetInfo(&KeResumeThread);
	KdPrint(("KeResumeThread = %llX\n", KeResumeThread.Address));

	UpdateOffsetInfo(&PspNotifyEnableMask);
	KdPrint(("PspNotifyEnableMask = %llX\n", PspNotifyEnableMask.Address));

	UpdateOffsetInfo(&MmSetPageProtection);
	KdPrint(("MmSetPageProtection = %llX\n", MmSetPageProtection.Address));

	UpdateOffsetInfo(&I8xWriteDataToKeyboardQueue);
	KdPrint(("I8xWriteDataToKeyboardQueue = %llX\n", I8xWriteDataToKeyboardQueue.Address));

	return TRUE;
}
