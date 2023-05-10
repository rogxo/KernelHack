/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#pragma once
#include "Includes.h"

namespace Comm
{
	enum OPERATION
	{
		ReadMem = 0x801,
		WriteMem,
		AllocMem,
		ProtectMem,
		ModuleBase,
		CodeInject,
	};

#pragma pack(8)
	typedef struct _REQUEST {
		ULONG Operation;
		PVOID Instruction;
	} REQUEST, * PREQUEST;

	typedef struct _COPY_MEMORY {
		ULONG ProcessId;
		PVOID Destination;
		PVOID Source;
		SIZE_T Size;
	} COPY_MEMORY, * PCOPY_MEMORY;

	typedef struct _ALLOC_MEMORY {
		ULONG ProcessId;
		PVOID Base;
		SIZE_T Size;
	} ALLOC_MEMORY, * PALLOC_MEMORY;

	typedef struct _MODULE_BASE {
		ULONG ProcessId;
		PCHAR ModuleName;
		PVOID PBase;
	} MODULE_BASE, * PMODULE_BASE;

	typedef struct _CODE_INJECT {
		ULONG ProcessId;
		PBYTE Shellcode;
		SIZE_T Size;
	} CODE_INJECT, * PCODE_INJECT;

#pragma pack()

	void RequestHandler(PREQUEST Request);

	namespace DeviceIoControl {
		NTSTATUS DispatchIoCtrl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
		BOOLEAN Initialize(PDRIVER_OBJECT DriverObject);
		BOOLEAN Unload(PDRIVER_OBJECT DriverObject);
	}

	namespace BoundCallback	{
		BOUND_CALLBACK_STATUS CallbackFunc();
		BOOLEAN Initialize();
		BOOLEAN Unload();
	}

	namespace RegistryCallback
	{
		NTSTATUS RegistryCallback(
			PVOID CallbackContext,
			PVOID Argument1,
			PVOID Argument2);
		BOOLEAN Initialize();
		BOOLEAN Unload();
	}

	namespace IrpHijack {
		NTSTATUS DetourDeviceControl(
			PDEVICE_OBJECT DeviceObject,
			PIRP Irp);
		BOOLEAN Initialize();
		BOOLEAN Unload();
	}
};

