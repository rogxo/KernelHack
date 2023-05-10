/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#pragma once
#include "Includes.h"

namespace Offsets
{
	typedef struct _OFFSETINFO
	{
		PCHAR Module;
		PCHAR Section;
		PCHAR InFunction;
		PCHAR Pattern;
		PCHAR Mask;
		ULONG64 Offset;
		ULONG64 Address;
	}OFFSETINFO, * POFFSETINFO;

	extern OFFSETINFO CmCallbackListHead;
	extern OFFSETINFO PoolBigPageTable;
	extern OFFSETINFO PiDDBLock;
	extern OFFSETINFO PiDDBCacheTable;
	extern OFFSETINFO KeSuspendThread;
	extern OFFSETINFO KeResumeThread;
	extern OFFSETINFO PspNotifyEnableMask;
	extern OFFSETINFO MmSetPageProtection;

	BOOLEAN UpdateOffsetInfo(POFFSETINFO OffsetInfo);

	BOOLEAN Initialize();
}