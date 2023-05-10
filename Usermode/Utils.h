/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	MIT

--*/
#pragma once
#include <TlHelp32.h>
#include <Windows.h>

DWORD GetProcessIdByProcessName(const CHAR ProcessName[MAX_PATH])
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	do {
		if (!strcmp(pe32.szExeFile, ProcessName))
		{
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return FALSE;
}