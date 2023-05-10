#include "I8042Interface.h"
#include "Imports.h"
#include "Offsets.hpp"
#include "Utils.hpp"


namespace I8042Interface 
{
	PDEVICE_OBJECT I8042DeviceObject;
}

BOOLEAN I8042Interface::InitializeI8042Interface()
{
	PDRIVER_OBJECT i8042;
	UNICODE_STRING i8042prt = RTL_CONSTANT_STRING(L"\\Driver\\i8042prt");
	NTSTATUS status = ObReferenceObjectByName(&i8042prt, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&i8042);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}
	ObDereferenceObject(i8042);
	I8042DeviceObject = i8042->DeviceObject;
	if (!I8042DeviceObject) {
		return FALSE;
	}
	if (I8042DeviceObject->NextDevice) {
		I8042DeviceObject = I8042DeviceObject->NextDevice;
	}
	return TRUE;
}

BOOLEAN I8042Interface::I8xWriteDataToKeyboardQueue(PVOID KeyboardExtension, IN PKEYBOARD_INPUT_DATA InputData)
{
	typedef BOOLEAN(*pfnI8xWriteDataToKeyboardQueue)(PVOID KeyboardExtension, PKEYBOARD_INPUT_DATA InputData);
	if (Offsets::I8xWriteDataToKeyboardQueue.Address) {
		return ((pfnI8xWriteDataToKeyboardQueue)Offsets::I8xWriteDataToKeyboardQueue.Address)(KeyboardExtension, InputData);
	}
	return FALSE;
}

void I8042Interface::Test()
{

	//do test

	//00 00 5b 00 02 00 00 00-00 00 00 00 00 00 00 00	//Win make
	//00 00 5b 00 03 00 00 00-00 00 00 00 00 00 00 00	//Win release

	//00 00 1e 00 00 00 00 00-00 00 00 00 00 00 00 00	//A make
	//00 00 1e 00 01 00 00 00-00 00 00 00 00 00 00 00	//A release

	KEYBOARD_INPUT_DATA data1 = {
		0x0000,
		0x005b,
		0x0002,
		0x0000,
		0x00000000,
	};

	KEYBOARD_INPUT_DATA data2 = {
		0x0000,
		0x005b,
		0x0003,
		0x0000,
		0x00000000,
	};

	//I8042Interface::I8042DeviceObject = (PDEVICE_OBJECT)0xffffa606d8ef03e0;

	if (I8042Interface::InitializeI8042Interface())
	{
		DbgPrint("[*] I8042DeviceObject = %p\n", I8042Interface::I8042DeviceObject);

		for (size_t i = 0; i < 10; i++)
		{
			DbgPrint("[*] Calling I8xWriteDataToKeyboardQueue\n");
			I8042Interface::I8xWriteDataToKeyboardQueue(I8042Interface::I8042DeviceObject->DeviceExtension, &data1);
			KeInsertQueueDpc((PRKDPC)((char*)I8042Interface::I8042DeviceObject->DeviceExtension + 0x2E0),
				I8042Interface::I8042DeviceObject->CurrentIrp, NULL);

			I8042Interface::I8xWriteDataToKeyboardQueue(I8042Interface::I8042DeviceObject->DeviceExtension, &data2);
			KeInsertQueueDpc((PRKDPC)((char*)I8042Interface::I8042DeviceObject->DeviceExtension + 0x2E0),
				I8042Interface::I8042DeviceObject->CurrentIrp, NULL);

			Utils::Sleep(100);
		}
	}

}
