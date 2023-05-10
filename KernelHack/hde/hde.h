#pragma once

#if defined(_AMD64_)
#include "hde64.h"
typedef hde64s hdes;
#define hde_disasm hde64_disasm
#elif defined(_X86_)
#include "hde32.h"
typedef hde32s hdes;
#define hde_disasm hde32_disasm
#else
#error Unsupported architecture
#endif
