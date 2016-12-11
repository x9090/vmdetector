#include <windows.h>
#include <stdio.h>
#include "chkrdtsc.h"

//////////////////////////////////////////////////////////////////////////
// Macros
//////////////////////////////////////////////////////////////////////////
#define LODWORD(l) ((DWORD)((DWORDLONG)(l)))
#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l)>>32)&0xFFFFFFF

// Ref: Locky's DLL payload Oct 2016
// 6373858656F8D87F59E5FF27AB20976DC1AC7D43457640919D415978650A2124
BOOLEAN CheckRDTSCHookUsingHeuristic()
{
    unsigned __int64 tsc1;
    unsigned __int64 tsc2;
    unsigned __int64 tsc3;
    int ratio = 0;
    int loop = 20;
    int count = 0;

    // Get first rdtsc value
    do{
        tsc1 = __rdtsc();

        // Waste some cycles - should be faster than CloseHandle on bare metal
        GetOEMCP();

        tsc2 = __rdtsc();

        // Waste some cycles - slightly longer than GetOEMCP() on bare metal
        CloseHandle(0);

        tsc3 = __rdtsc();

        ratio = (LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1));

#ifdef _DEBUG
        printf("%s:%d Iteration %02d\n", __FUNCTION__, __LINE__, count);
        printf("    TSC 1: %08x\n", LODWORD(tsc1));
        printf("    TSC 2: %08x\n", LODWORD(tsc2));
        printf("    TSC 3: %08x\n", LODWORD(tsc3));
        printf("    Ratio: %08x\n", ratio);
#endif
        /* CloseHandle with invalid handle should take more cycles on native machine */
        if (ratio > 3)
            return FALSE;

        count++;
    } while (count < loop);

    /* Failed in VM/RDTSC hook check */
    return TRUE;
}

/***********************************************************************
* This is the Locky anti - VM code from 21 June 2016 (sample SHA1 25f8f920f946887e0fa86ea46842f8e3f4506f53)
*
* Some VM products may behave significantly differently to a real system
* with regards to timing of code execution.
*
* GetProcessHeap() may take significantly longer in a VM than a real env.
*
* Virtualised TSCs can also be problematic.
*
* Multiple processor cores assigned to a VM may also worsen this problem.
*
* See http ://blog.badtrace.com/post/rdtsc-x86-instruction-to-detect-vms/ 
*
* Ref: https://blogs.forcepoint.com/security-labs/locky-returned-new-anti-vm-trick
************************************************************************/

BOOLEAN PassRDTSCUsingAPIHeuristic()
{
    unsigned __int64 tsc1;
    unsigned __int64 tsc2;
    unsigned __int64 tsc3;
    int ratio = 0;
    int i = 0;

    // Try this 10 times in case of small fluctuations
    for (i = 0; i < 10; i++)
    {
        tsc1 = __rdtsc();

        // Waste some cycles - should be faster than CloseHandle on bare metal
        GetProcessHeap();

        tsc2 = __rdtsc();

        // Waste some cycles - slightly longer than GetProcessHeap() on bare metal
        CloseHandle(0);

        tsc3 = __rdtsc();

        ratio = (LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1));
#ifdef _DEBUG

        printf("%s:%d Iteration %02d\n", __FUNCTION__, __LINE__, i);
        printf("    TSC 1: %08x\n", LODWORD(tsc1));
        printf("    TSC 2: %08x\n", LODWORD(tsc2));
        printf("    TSC 3: %08x\n", LODWORD(tsc3));
        printf("    Ratio: %08x\n", ratio);

#endif
        // Did it take at least 10 times more CPU cycles to perform CloseHandle than it took to perform GetProcessHeap()?
        if (ratio >= 10)
            return TRUE;
    }

    // We consistently saw a small ratio of difference between GetProcessHeap and CloseHandle execution times
    // so we're probably in a VM!
    return FALSE;
}
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