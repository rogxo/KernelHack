#pragma once
#include <ntifs.h>
#include <ntddmou.h>
#include <ntddkbd.h>
#include <ntdd8042.h>

namespace I8042Interface 
{
    //typedef struct _KEYBOARD_INPUT_DATA {
    //    USHORT UnitId;
    //    USHORT MakeCode;
    //    USHORT Flags;
    //    USHORT Reserved;
    //    ULONG ExtraInformation;
    //} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;

    extern PDEVICE_OBJECT I8042DeviceObject;

    BOOLEAN InitializeI8042Interface();

    BOOLEAN I8xWriteDataToKeyboardQueue(PVOID KeyboardExtension, IN PKEYBOARD_INPUT_DATA InputData);

    void Test();
}
