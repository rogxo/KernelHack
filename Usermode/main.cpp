/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	MIT

--*/
#include <stdio.h>
#include <windows.h>
#include "UmComm.h"
#include "Utils.h"

void test_get_module_base(int pid)
{
	Comm::MODULE_BASE Data = { 0 };
	Comm::REQUEST req = { 0 };
	uintptr_t Base;

	Data.ProcessId = pid;
	Data.ModuleName = "RainbowSix.exe";
	Data.PBase = &Base;

	req.Operation = Comm::ModuleBase;
	req.Instruction = &Data;

	Comm::RegistryCallback::Request(&req);

	printf("Buffer = %llX\n", Base);
}

void test_read_memory()
{
	Comm::COPY_MEMORY Data = { 0 };
	Comm::REQUEST req = { 0 };

	ULONG64 Buffer = 0;

	Data.ProcessId = 4904;
	Data.Source = (PVOID)0x210C176F6B0;
	Data.Destination = &Buffer;
	Data.Size = sizeof(Buffer);

	req.Operation = Comm::ReadMem;
	req.Instruction = &Data;

	[&]()->void {
		SIZE_T number = 1000000;
		ULONG64 now = GetTickCount64();
		for (SIZE_T i = 0; i < number; i++) {
			//Comm::RegistryCallback::Request(&req);
			Comm::HijackIrp::Request(&req);
			//Comm::DeviceIoControl::Request(&req);
		}
		printf("Read %lld times cost = %lfs\n",
			number,
			(double)(GetTickCount64() - now) / 1000);
	}();

	printf("Buffer = %llX\n", Buffer);
}

void test_code_inject()
{
	Comm::CODE_INJECT Data = { 0 };
	Comm::REQUEST req = { 0 };
	req.Operation = Comm::CodeInject;
	req.Instruction = &Data;

	BYTE Shellcode[] = {
		0x50,0x51,0x52,0x53,								//push rax,rcx,rdx,rbx
		0x6A,0xFF,											//Dummy for rsp
		0x55,0x56,0x57,										//push rbp,rsi,rdi
		0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,

		0xB9,0x00,0x00,0x00,0x00,							//mov ecx, 0
		0xBA,0x00,0x00,0x00,0x00,							//mov edx, 0
		0x41,0xB8,0x00,0x00,0x00,0x00,						//mov r8d, 0
		0x41,0xB9,0x01,0x00,0x00,0x00,						//mov r9d, 1
		0x48,0xB8,0x10,0xAC,0x1C,0x9E,0xFA,0x7F,0x00,0x00,	//mov rax, <user32.MessageBoxA>
		0xFF,0xD0, 											//call rax

		0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,
		0x5F,0x5E,0x5D,0x5B,0x5B,0x5A,0x59,0x58,			//pop rdi,rsi,rbp,rbx,rbx,rdx,rcx,rax
		0xC3												//ret
	};

	HMODULE user32 = LoadLibrary("user32.dll");
	if (!user32)	return;
	*(PULONG64)(Shellcode + 49) = (ULONG64)GetProcAddress(user32, "MessageBoxA");

	//Data.ProcessId = GetProcessIdByProcessName("notepad.exe");
	Data.ProcessId = GetProcessIdByProcessName("Ke64v1.4.exe");
	Data.Shellcode = Shellcode;
	Data.Size = sizeof(Shellcode);

	Comm::RegistryCallback::Request(&req);
}

int main(void) 
{
	//Comm::RegistryCallback::Initialize();
	Comm::HijackIrp::Initialize();
	//Comm::DeviceIoControl::Initialize();
	//test_get_module_base(GetProcessIdByProcessName("RainbowSix.exe"));
	test_read_memory();
	//test_code_inject();

	getchar();
	return 0;
}
