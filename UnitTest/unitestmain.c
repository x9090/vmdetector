#include <windows.h>
#include <stdio.h>
#include "../VmDetector/vmdetector.h"

void wmain()
{
	/* ============================================================ */
	/* Test case #1: Get whitelisting process name from config file */
	/* ============================================================ */
	/*
	CHAR **whitelist = GetExclusionFileName();

	if (whitelist != NULL)
	{
		wprintf(L"[+] Whitelist name: \n");
		while (*whitelist != NULL)
		{
			wprintf(L"   %s\n", *whitelist);
			whitelist++;
		}
	}*/

	/* ============================================================ */
	/* Test case #2: Get RDTSC type from config file */
	/* ============================================================ */
	/*
	// Get RDTSC method definition from vmdetector.ini configuration file
	DWORD dwRdtscMethod = GetRdtscDefinition(1);

	// Get RDTSC desired value from vmdetector.ini configuration file
	DWORD dwRdtscValue = GetRdtscDefinition(2);

	// If not defined in the configuration file, use value in g_RDTSC_CONSTANT instead
	if (dwRdtscValue == -1)
		dwRdtscValue = 199;

	wprintf(L"[+] RDTSC method: %d\n", dwRdtscMethod);
	wprintf(L"[+] RDTSC value: %d\n", dwRdtscValue);
	*/

	/* ================================================================== */
	/* Test case #3: Get machine's disk drive information by querying WMI */
	/* ================================================================== */
	//if (WmiCheckInit())
	//{
	//	/*if (WmiCheckWin32Drives())
	//		wprintf(L"Found vmware/virtual string from disk drive\n");

	//	if (WmiCheckWin32CDROMDrive())
	//		wprintf(L"Found vmware/virtual string from optical drive\n");*/

	//	if (WmiCheckWin32VideoController())
	//	{
	//		wprintf(L"Found vmware/virtual string from video controller\n");

	//		// Patch VMware string
	//		wprintf(L"Patching registry key.\n");
	//		if (!VMRegPatcher(PATCH_WMI_VIDEOCONTROLLER_REGKEY))
	//			wprintf(L"Failed patching.\n");
	//		else
	//			wprintf(L"Patched successfully.\n");

	//		// Block registry access
	//		wprintf(L"Block relevant VideoController registry access.\n");
	//		BlockAccessVmPciReg();
	//		wprintf(L"Block relevant VideoController registry access successfully!\n");
	//	}
	//}
	//else
	//	wprintf(L"[+] WMI initialization failed!\n");

	//WmiCleanup();

	/* ============================================================== */
	/* Test case #4: Get registry keys to be patched from config file */
	/* ============================================================== */
	//CHAR **RegKeys = GetRegKeysToBePatched();
	//int index = 1;

	//if (RegKeys != NULL)
	//{
	//	wprintf(L"[+] Registry keys: \n");
	//	while (*RegKeys != NULL)
	//	{
	//		printf(" [%d] %s\n", index++, *RegKeys);
	//		RegKeys++;
	//	}
	//}

	/* ============================================================ */
	/* Test case #5: Check number of CPU cores
	/* ============================================================ */
	//CheckCPUCores();
	//printf("Number of CPU cores: %d\n", g_NumberOfProcessors);

    /* ============================================================ */
    /* Test case #6: Check VM HDD using setupapi
    /* ============================================================ */
    //BOOL bIsVmHdd = CheckIsVmHdd();
    //printf("Running in virtual machine? %s", bIsVmHdd ? "TRUE" : "FALSE");

    /* ============================================================ */
    /* Test case #7: RDTSC hook check?
    /* ============================================================ */
    printf("RDTSC hook detection using heuristic #1 (GetProcessHeap & CloseHandle interval)? %s\n", PassRDTSCUsingAPIHeuristic() ? "FALSE" : "TRUE");
    printf("RDTSC hook detection using heuristic #2 (GetOEMCP & CloseHandle interval)? %s\n", CheckRDTSCHookUsingHeuristic() ? "TRUE" : "FALSE");

    system("pause");
	return;
}