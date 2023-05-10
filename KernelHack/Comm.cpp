/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Comm.hpp"
#include "Memory.hpp"
#include "Utils.hpp"
#include "Process.hpp"
#include "skCrypter.h"
#include "CallStack-Spoofer.h"

void Comm::RequestHandler(PREQUEST Request)
{
	SPOOF_FUNC;

	if (!Request->Instruction)
		return;

	if (Request->Operation == ReadMem) 
	{
		PCOPY_MEMORY Instruction = (PCOPY_MEMORY)Request->Instruction;
		PEPROCESS Process = Utils::GetProcessByProcessId((HANDLE)Instruction->ProcessId);
		if (!Process) {
			return;
		}

		Memory::ReadProcessMemory(
			Process,
			Instruction->Source, 
			Instruction->Destination, 
			Instruction->Size);
	}
	else if (Request->Operation == WriteMem)
	{
		PCOPY_MEMORY Instruction = (PCOPY_MEMORY)Request->Instruction;
		PEPROCESS Process = Utils::GetProcessByProcessId((HANDLE)Instruction->ProcessId);
		if (!Process) {
			return;
		}
		Memory::WriteProcessMemory(Utils::GetProcessByProcessId(
			(HANDLE)Instruction->ProcessId),
			Instruction->Source, 
			Instruction->Destination,
			Instruction->Size);
	}
	else if (Request->Operation == AllocMem)
	{
		PALLOC_MEMORY Instruction = (PALLOC_MEMORY)Request->Instruction;
		PEPROCESS Process = Utils::GetProcessByProcessId((HANDLE)Instruction->ProcessId);
		if (!Process) {
			return;
		}
		PVOID Base = Instruction->Base;
		SIZE_T Size = Instruction->Size;
		Process::SafeAllocateExecuteMemory(Process, &Base, &Size);
	}
	else if (Request->Operation == ProtectMem)
	{
	}
	else if (Request->Operation == ModuleBase)
	{
		PEPROCESS Process = { 0 };
		PMODULE_BASE Instruction = (PMODULE_BASE)Request->Instruction;
		if ((HANDLE)Instruction->ProcessId 
			&& NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Instruction->ProcessId, &Process)))
		{
			*(PVOID*)Instruction->PBase = Process::GetModuleBase(Process, Instruction->ModuleName);
		}
	}
	else if (Request->Operation == CodeInject)
	{
		PCODE_INJECT Instruction = (PCODE_INJECT)Request->Instruction;
		PEPROCESS Process = Utils::GetProcessByProcessId((HANDLE)Instruction->ProcessId);
		if (!Process) {
			return;
		}
		Process::InjectShellcode(Process, Instruction->Shellcode, Instruction->Size);
	}
	return;
}

namespace Comm {
	namespace BoundCallback {
		PVOID hCallback = NULL;
	}
	namespace RegistryCallback{
		LARGE_INTEGER Cookie = { 0 };
		UNICODE_STRING Password = { 0 };
	}
	namespace IrpHijack{
		PDRIVER_DISPATCH OriginDeviceControl = NULL;
	}
}

NTSTATUS Comm::DeviceIoControl::DispatchIoCtrl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION IoStack;
	PREQUEST req = NULL;
	IoStack = IoGetCurrentIrpStackLocation(Irp);

	if (IoStack->Parameters.DeviceIoControl.IoControlCode == 0x9909099) {
		req = *(PREQUEST*)Irp->AssociatedIrp.SystemBuffer;
	}
	if (!req) {
		return STATUS_SUCCESS;
	}
	//设置IRP处理成功->告诉三环成功
	Irp->IoStatus.Status = STATUS_SUCCESS;
	//返回数据字节数
	Irp->IoStatus.Information = 0;
	//结束IRP处理流程
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

BOOLEAN Comm::DeviceIoControl::Initialize(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING uDeviceName = { 0 };	//设备名称
	UNICODE_STRING uSymLinkName = { 0 };	//符号链接名称
	RtlInitUnicodeString(&uDeviceName, skCrypt(L"\\device\\DeviceI0C0ntr0l"));	//初始化字符串-设备名称
	RtlInitUnicodeString(&uSymLinkName, skCrypt(L"\\dosdevices\\DeviceI0C0ntr0l"));	//初始化字符串-符号链接

	NTSTATUS status = STATUS_SUCCESS;	//状态
	PDEVICE_OBJECT DeviceObject = NULL;	//设备对象

	//创建设备对象
	status = IoCreateDevice(DriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice Fail");
		return FALSE;
	}

	DeviceObject->Flags |= DO_BUFFERED_IO;	//基于缓冲的IO

	status = IoCreateSymbolicLink(&uSymLinkName, &uDeviceName);	//创建符号链接
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(DeviceObject);
		DbgPrint("IoCreateSymbolicLink Fail");
		return FALSE;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoCtrl;
	return TRUE;
}

BOOLEAN Comm::DeviceIoControl::Unload(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING uSymlinkName = { 0 };
	RtlInitUnicodeString(&uSymlinkName, skCrypt(L"\\dosdevices\\DeviceI0C0ntr0l"));

	status = IoDeleteSymbolicLink(&uSymlinkName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoDeleteSymbolicLink Fail:%x\n", status);
		return FALSE;
	}
	if (DriverObject->DeviceObject != NULL)
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		DbgPrint("Unload Success\n");
		return TRUE;
	}
	return TRUE;
}


BOUND_CALLBACK_STATUS Comm::BoundCallback::CallbackFunc() {
	PKTHREAD thread = KeGetCurrentThread();
	PKTRAP_FRAME trap_frame = (PKTRAP_FRAME) * (DWORD64*)((char*)thread + 0x90);
	RequestHandler((PREQUEST)trap_frame->Rax);
	trap_frame->Rip += 4;
	return BoundExceptionHandled;
}

BOOLEAN Comm::BoundCallback::Initialize()
{
	hCallback = KeRegisterBoundCallback(CallbackFunc);
	if (!hCallback)
		return FALSE;
	return TRUE;
}

BOOLEAN Comm::BoundCallback::Unload()
{
	if (hCallback == NULL)
		return FALSE;
	return NT_SUCCESS(KeDeregisterBoundCallback(hCallback));
}

NTSTATUS Comm::RegistryCallback::RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	if ((ULONG64)Argument1 != RegNtPostSetValueKey)
		return STATUS_SUCCESS;

	PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
	PREG_SET_VALUE_KEY_INFORMATION preInfo = (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;

	if (RtlEqualUnicodeString(preInfo->ValueName, &Password, TRUE) == FALSE)
		return STATUS_SUCCESS;

	if (!preInfo->Data)
		return STATUS_SUCCESS;

	PREQUEST req = *(PREQUEST*)preInfo->Data;
	if (!req)
		return STATUS_SUCCESS;

	RequestHandler(req);
	return STATUS_SUCCESS;
}

BOOLEAN Comm::RegistryCallback::Initialize()
{
	RtlInitUnicodeString(&Password, skCrypt(L"P4ssw0rd"));
	ULONG64 RelayAddress = Utils::FindPatternImage(skCrypt("ntoskrnl.exe"), skCrypt(".text"),
		"\xFF\xE1", "xx");	//jmp rcx

	//NTSTATUS status = CmRegisterCallback(
	NTSTATUS status = Utils::SafeCmRegisterCallback(
		(PEX_CALLBACK_FUNCTION)RelayAddress,
		RegistryCallback, &Cookie);
	return NT_SUCCESS(status);
}

BOOLEAN Comm::RegistryCallback::Unload()
{
	if (Cookie.QuadPart == NULL)
		return FALSE;
	NTSTATUS status = Utils::SafeCmUnRegisterCallback(Cookie);
	return NT_SUCCESS(status);
}

NTSTATUS Comm::IrpHijack::DetourDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	SPOOF_FUNC_EX((uintptr_t)OriginDeviceControl);		//SpoofCallback

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	if (stack->Parameters.DeviceIoControl.IoControlCode != 0x9909099) {
		return OriginDeviceControl(DeviceObject, Irp);
	}
	PREQUEST req = *(PREQUEST*)Irp->AssociatedIrp.SystemBuffer;
	if (!req) {
		return STATUS_SUCCESS;
	}
	RequestHandler(req);	//Handle Request

	//设置IRP处理成功->告诉三环成功
	Irp->IoStatus.Status = STATUS_SUCCESS;
	//返回数据字节数
	Irp->IoStatus.Information = 0;
	//结束IRP处理流程
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

BOOLEAN Comm::IrpHijack::Initialize()
{
	PDRIVER_OBJECT DriverObject = Utils::GetDriverObjectByName(skCrypt(L"pci"));
	if (!DriverObject) {
		return FALSE;
	}
	OriginDeviceControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	//Sometimes trigger BSOD
	UCHAR ShellCode[] = {           //make a jmp
		0x50,															//push rax
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov  rax, 0xffffffffffffffff
		0x48, 0xC1, 0xC8, 0x28,											//ror  rax, 0x00
		0x48, 0x87, 0x04, 0x24,											//xchg qword [rsp], rax
		0xC3															//ret
	};
	auto CodeCave = (PVOID*)Utils::FindPatternImage(skCrypt("pci.sys"), skCrypt(".text"),
		"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
		skCrypt("xxxxxxxxxxxxxxxxxxxxxx"));
	if (!CodeCave) {
		return FALSE;
	}
	
	BYTE random = (ULONG64)CodeCave >> 16 & 0xFF;
	*(BYTE*)(ShellCode + 0xE) = random;
	*(ULONG64*)(ShellCode + 3) = Utils::__ROL__((ULONG64)DetourDeviceControl, random);

	if (!Memory::WriteToReadOnly(CodeCave, ShellCode, sizeof(ShellCode))) {
		return FALSE;
	}

	//InterlockedExchangePointer((PVOID*)&DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], DetourDeviceControl);
	InterlockedExchangePointer((PVOID*)&DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], CodeCave);
	return TRUE;
}

BOOLEAN Comm::IrpHijack::Unload()
{
	BYTE Dummy[] = { 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
					 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
					 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };
	if (OriginDeviceControl) {
		PDRIVER_OBJECT DriverObject = Utils::GetDriverObjectByName(L"pci");
		PVOID CodeCave = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		InterlockedExchangePointer((PVOID*)&DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], OriginDeviceControl);
		Memory::WriteToReadOnly(CodeCave, Dummy, sizeof(Dummy));
	}
	return TRUE;
}

