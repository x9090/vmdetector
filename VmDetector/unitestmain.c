//#include <windows.h>
//#include <stdio.h>
//#include "vmdetector.h"
//
//void main()
//{
//	/*CHAR **whitelist = GetExclusionFileName();
//
//	if (whitelist != NULL)
//	{
//		printf("[+] Whitelist name: \n");
//		while (*whitelist != NULL)
//		{
//			printf("   %s\n", *whitelist);
//			whitelist++;
//		}
//	}*/
//
//	// Get RDTSC method definition from vmdetector.ini configuration file
//	DWORD dwRdtscMethod = GetRdtscDefinition(1);
//
//	// Get RDTSC desired value from vmdetector.ini configuration file
//	DWORD dwRdtscValue = GetRdtscDefinition(2);
//
//	// If not defined in the configuration file, use value in g_RDTSC_CONSTANT instead
//	if (dwRdtscValue == -1)
//		dwRdtscValue = 199;
//
//	printf("[+] RDTSC method: %d\n", dwRdtscMethod);
//	printf("[+] RDTSC value: %d\n", dwRdtscValue);
//}