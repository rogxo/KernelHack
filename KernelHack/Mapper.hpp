/*++

Copyright (c) 2020-2025, Rog. All rights reserved.

Author:
	Rog

License:
	GPL

--*/
#include "Includes.h"

namespace Mapper
{
	BOOLEAN ResolveImports(uintptr_t imageBase);

	void ResolveRelocations(uintptr_t imageBase, uintptr_t newBase, uintptr_t delta);

	NTSTATUS MapDriver(PVOID data, SIZE_T size);

	NTSTATUS MapDriverFromFile(PUNICODE_STRING FilePath);
}