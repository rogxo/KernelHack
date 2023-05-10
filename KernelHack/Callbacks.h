/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#pragma once
#include <ntdef.h>

namespace Callbacks
{
	typedef struct _NOTIFICATION_CALLBACKS {
		ULONG_PTR PspCreateProcessNotifyRoutine;
		ULONG_PTR PspCreateThreadNotifyRoutine;
		ULONG_PTR PspLoadImageNotifyRoutine;
		ULONG_PTR KeBugCheckCallbackHead;
		ULONG_PTR KeBugCheckReasonCallbackHead;
		ULONG_PTR CmCallbackListHead;
		ULONG_PTR IopNotifyShutdownQueueHead;
		ULONG_PTR IopNotifyLastChanceShutdownQueueHead;
		ULONG_PTR ObProcessCallbackHead;
		ULONG_PTR ObThreadCallbackHead;
		ULONG_PTR ObDesktopCallbackHead;
		ULONG_PTR SeFileSystemNotifyRoutinesHead;
		ULONG_PTR SeFileSystemNotifyRoutinesExHead;
		ULONG_PTR PopRegisteredPowerSettingCallbacks;
		ULONG_PTR RtlpDebugPrintCallbackList;
		ULONG_PTR IopFsNotifyChangeQueueHead;
		ULONG_PTR IopDiskFileSystemQueueHead;
		ULONG_PTR IopCdRomFileSystemQueueHead;
		ULONG_PTR IopTapeFileSystemQueueHead;
		ULONG_PTR IopNetworkFileSystemQueueHead;
		ULONG_PTR DbgkLmdCallbacks;
		ULONG_PTR PsAltSystemCallHandlers;
		ULONG_PTR CiCallbacks;
		ULONG_PTR ExpHostListHead;
		ULONG_PTR ExpCallbackListHead;
		ULONG_PTR PoCoalescingCallbacks;
		ULONG_PTR PspPicoProviderRoutines;
		ULONG_PTR KiNmiCallbackListHead;
		ULONG_PTR PspSiloMonitorList;
		ULONG_PTR EmpCallbackListHead;
	} NOTIFICATION_CALLBACKS, * PNOTIFICATION_CALLBACKS;
};

