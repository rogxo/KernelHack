/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	MIT

--*/
#pragma once
#include "UmComm.h"

namespace Comm {
	namespace DeviceIoControl {
		HANDLE hDevice;
	}
	namespace RegistryCallback {
		UNICODE_STRING SubKeyName;
		UNICODE_STRING ValueName;
		OBJECT_ATTRIBUTES ObjectAttributes;
	}
	namespace HijackIrp {
		HANDLE hDevice;
	}
}

bool Comm::DeviceIoControl::Initialize()
{
	hDevice = CreateFile("\\\\.\\DeviceI0C0ntr0l", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return false;
	}
	return true;
}

void Comm::DeviceIoControl::Request(PREQUEST req)
{
	ULONG retLen;
	::DeviceIoControl(hDevice, 0x9909099, &req, sizeof(req), NULL, 0, &retLen, NULL);
}

#ifndef _WIN64
void Comm::BonudCallback::Request(PREQUEST req)
{
	__asm {
		mov eax, req
		bound di, dword ptr[ebp]
	}
}
#endif

bool Comm::RegistryCallback::Initialize() {
	HMODULE hNtdll = GetModuleHandle("ntdll.dll");
	if (!hNtdll) {
		return false;
	}
	RtlInitUnicodeString(&SubKeyName, L"\\registry\\machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers");
	RtlInitUnicodeString(&ValueName, L"P4ssw0rd");
	InitializeObjectAttributes(&ObjectAttributes, &SubKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	return true;
}

void Comm::RegistryCallback::Request(PREQUEST req)
{
	NTSTATUS status = 0;
	HANDLE KeyHandle;
	
	status = NtOpenKey(&KeyHandle, KEY_SET_VALUE, &ObjectAttributes);
	if (NT_SUCCESS(status)) {
		NtSetValueKey(KeyHandle, &ValueName, 0, REG_QWORD, &req, sizeof uintptr_t);
		NtClose(KeyHandle);
	}
}

bool Comm::HijackIrp::Initialize()
{
	hDevice = CreateFile("\\\\.\\PciControl", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return false;
	}
	return true;
}

void Comm::HijackIrp::Request(PREQUEST req)
{
	ULONG retLen;
	::DeviceIoControl(hDevice, 0x9909099, &req, sizeof(req), NULL, 0, &retLen, NULL);
}

