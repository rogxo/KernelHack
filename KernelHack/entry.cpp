/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Includes.h"
#include "Memory.hpp"
#include "Utils.hpp"
#include "Comm.hpp"
#include "Mapper.hpp"
#include "Offsets.hpp"
#include "Process.hpp"
#include "skCrypter.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint(skCrypt("DriverObject = %p\n"), DriverObject);

	if (Offsets::Initialize() == FALSE)	{
		DbgPrint(skCrypt("Unsupport System!!!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	if (DriverObject) {
		DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObject)-> VOID {
			UNREFERENCED_PARAMETER(DriverObject);
			//Comm::RegistryCallback::Unload();
			//Comm::DeviceIoControl::Unload(DriverObject);
			//Comm::IrpHijack::Unload();
		};

		//Comm::RegistryCallback::Initialize();
		//Comm::DeviceIoControl::Initialize(DriverObject);
		//Comm::IrpHijack::Initialize();
		//return STATUS_SUCCESS;

		PLDR_DATA_TABLE_ENTRY LdrData = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		status = Mapper::MapDriverFromFile(&LdrData->FullDllName);
		LdrData->BaseDllName.Length = 0;
		Memory::CleanPiDDBCache(DriverObject);
		return STATUS_UNSUCCESSFUL;
	}
	else {
		//Comm::RegistryCallback::Initialize();
		//Comm::BonudCallback::Initialize();
		Comm::IrpHijack::Initialize();
	}

	return status;
}
