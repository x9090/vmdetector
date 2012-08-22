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

BOOLEAN CheckRTDSC()
{
	int rdtsc;

	rdtsc = get_rdtsc_val();

	// Running in VM
	if (rdtsc > 0xFF)
		return TRUE;
	else
		return FALSE;
}

BOOLEAN patch_rdtsc()
{
	BOOLEAN bRdtscPatch = FALSE;


	return bRdtscPatch;
}