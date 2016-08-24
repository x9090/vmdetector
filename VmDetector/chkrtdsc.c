#include <windows.h>
#include <stdio.h>
#include "chkrdtsc.h"

//
// Can be bypassed by using Intel VT-x or AMD-V
// https://eof-project.net/oldf/viewtopic.php?id=405
//
unsigned int get_rdtsc_val()
{
	unsigned int rdtsc_val;

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
// Useful against RDTSC hook
/*
	1 => 6d2d07 434375a7
	or eax, eax
	jump out if zero
	push edx1

	sleep(2000)

	2 => 6d2d24 1dcae18e
	cmp(edx2, edx1)

	3 => 6d2d66 4e404415
	add edx3, 1

	4 => 6d2d85 60f64e68
	cmp(edx3, edx4)

*/
BOOLEAN inspect_high_bit_rdtsc()
{
	unsigned int eax_val1, edx_val1;
	unsigned int eax_val2, edx_val2;


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

	if (eax_val1 == 0)
		return TRUE;

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
	// The edx1&edx2 value shouldn't be the same if RDTSC is not hooked
	// As Sleep call will increase tick count value significantly
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
	unsigned int rdtsc;

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