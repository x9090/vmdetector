#include <windows.h>
#include "chkcpucores.h"

//
// First found from Dyreza
//
int g_NumberOfProcessors = 0;
BOOLEAN CheckCPUCores()
{
	__asm{
			push    eax
			push    ebx
			mov		eax, fs:[0x30]
			add		eax, 0x64
			mov     ebx, [eax]
			mov		g_NumberOfProcessors, ebx
			pop     ebx
			pop     eax
	}

	// One CPU cores, most likely in VM
	if (g_NumberOfProcessors == 1)
		return TRUE;
	else
		return FALSE;
}
