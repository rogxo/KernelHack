/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	MIT

--*/
#include <Windows.h>
#include "ntdll.h"

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
		DllInject,
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
		LPCSTR ModuleName;
		PVOID PBase;
	} MODULE_BASE, * PMODULE_BASE;

	typedef struct _CODE_INJECT {
		ULONG ProcessId;
		PBYTE Shellcode;
		SIZE_T Size;
	} CODE_INJECT, * PCODE_INJECT;

	typedef struct _DLL_INJECT {
		ULONG ProcessId;
		LPCSTR DllPath;
	} DLL_INJECT, * PDLL_INJECT;
#pragma pack()

	namespace DeviceIoControl
	{
		bool Initialize();
		void Request(PREQUEST req);
	}

	namespace BoundCallback
	{
		void Request(PREQUEST req);
	}

	namespace RegistryCallback
	{
		bool Initialize();
		void Request(PREQUEST req);
	}

	namespace HijackIrp
	{
		bool Initialize();
		void Request(PREQUEST req);
	}
}