#include <windows.h>
#include "chkrdtsc.h"

//
// Can be bypassed by using Intel VT-x or AMD-V
// https://eof-project.net/oldf/viewtopic.php?id=405
//
int get_rdtsc_val()
{
	int rdtsc_val;

	__asm{
		RDTSC
		xor		ecx, ecx
		add		ecx, eax
		RDTSC	
		sub		eax, ecx
		mov		rdtsc_val, eax
	}

	return rdtsc_val;
}

// Ref: 0667f24a6a68fcc1ae04a61818ef88092ee90612
BOOLEAN inspect_high_bit_rdtsc()
{
	int eax_val1, edx_val1;
	int eax_val2, edx_val2;


	// Get first rdtsc value
	__asm{
		push	edx
		push	eax
		RDTSC
		mov		edx_val1, edx
		mov		eax_val1, eax
		pop		eax
		pop		edx
	}
	
	// Sleep for 2 seconds
	Sleep(2000);

	// Get second rdtsc value
	__asm{
		push	edx
		push	eax
		RDTSC
		mov		edx_val2, edx
		mov		eax_val2, eax
		pop		eax
		pop		edx
	}

	// Compare the high bit value
	if (edx_val2 == edx_val1)
		return TRUE;

	// Get third rdtsc value
	__asm{
		push	edx
		push	eax
		RDTSC
		mov		edx_val1, edx
		mov		eax_val1, eax
		pop		eax
		pop		edx
	}

	// Get fourth rdtsc value
	__asm{
		push	edx
		push	eax
		RDTSC
		mov		edx_val2, edx
		mov		eax_val2, eax
		pop		eax
		pop		edx
	}

	if (edx_val2+1 <= edx_val1)
		return TRUE;

	return FALSE;

}
BOOLEAN CheckRTDSC()
{
	int rdtsc;

	rdtsc = get_rdtsc_val();

	// Running in VM
	if (rdtsc > 0xFF || inspect_high_bit_rdtsc())
		return TRUE;
	else
		return FALSE;
}

BOOLEAN patch_rdtsc()
{
	BOOLEAN bRdtscPatch = FALSE;


	return bRdtscPatch;
}