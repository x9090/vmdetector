#include <windows.h>
#include <stdio.h>
#include "vmdetector.h"

#define SYS_SERVICE_NAME L"iminnocent"
#define SYS_DISPLAY_NAME L"ImInnocent Detector Driver"
#define SYS_DEVICE_NAME L"\\\\.\\iminnocent"

int main(int args, WCHAR *argv[])
{
	CHAR	strCPUID[13] = {0};
	BOOLEAN	bInstallDrv;
	HANDLE  hDevObj;
	DWORD   dwBytesReturned;
	DWORD	dwResult;
	int i=1;
	int j=0;
	int k=0;
	int arrFixable[10] = {0};
	
	wprintf(L"[%d] Checking Hard Disk Drive device model: ", i);
	if (CheckStorageProperty()) 
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
		wprintf(L"Failed ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
		wprintf(L"(FIXABLE)\n");
		arrFixable[j++] = i;
	}
	else 
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
		wprintf(L"Passed\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	}
	i++;

	wprintf(L"[%d] Checking CPUID: ", i);
	if (CheckHyperV())
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
		wprintf(L"Failed \n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	}
	else 
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
		wprintf(L"Passed\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	}
	i++;

	wprintf(L"[%d] Checking RTDSC: ", i);
	if (CheckRTDSC())
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
		wprintf(L"Failed ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
		wprintf(L"(FIXABLE)\n");
		arrFixable[j++] = i;
	}
	else 
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
		wprintf(L"Passed\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	}
	i++;

	wprintf(L"[%d] Checking \"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\": ", i);
	if (CheckVmDiskReg())
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
		wprintf(L"Failed ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
		wprintf(L"(FIXABLE)\n");
		arrFixable[j++] = i;
	}
	else 
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
		wprintf(L"Passed\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	}
	i++;

	wprintf(L"[%d] Checking registry \"SYSTEM\\CurrentControlSet\\Enum\\IDE\": ", i);
	if (CheckVmIdeReg())
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
		wprintf(L"Failed ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
		wprintf(L"(FIXABLE)\n");
		arrFixable[j++] = i;
	}
	else 
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
		wprintf(L"Passed\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	}
	i++;

	// At least one fixable Anti-VM tricks
	if (j > 0)		
	{
		wprintf(L"\n\nPatching \"FIXABLE\" items...\n\n");

		// Install VmDetectorSys driver
		bInstallDrv = InstallAndStartVmDetectorDriver(L"\\\\?\\C:\\Windows\\system32\\drivers\\VmDetectorSys.sys");

		if (!bInstallDrv && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) 
			wprintf(L"[+] The service was already started and running.\n");
		else if (!bInstallDrv && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
			wprintf(L"[+] The service was already marked for deletion.\n");
		else if (!bInstallDrv && GetLastError() != ERROR_SUCCESS) 
		{
			wprintf(L"[-] Failed to install and load the driver. (0x%08x)\n", GetLastError());
			return;
		}
	}

	// Handle all the fixable Anti-VM tricks
	while (k < j)
	{
		switch(arrFixable[k])
		{
			case 1: // Item 1
				wprintf(L"[+] Patching Device Model... ");
				dwResult = FALSE;
				hDevObj = CreateFile(
					SYS_DEVICE_NAME, 
					GENERIC_READ|GENERIC_WRITE, 
					FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (!DeviceIoControl(
					hDevObj, 
					IOCTL_VMDETECTORSYS_DEVMODEL_FIX, 
					NULL, 0, 
					&dwResult, sizeof(dwResult), 
					&dwBytesReturned, 
					NULL)) wprintf(L"\n[-] Failed in operation IOCTL_VMDETECTORSYS_DEVMODEL_FIX. (0x%08x)", GetLastError());
				if (dwResult)
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
					wprintf(L" Succeeded\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}
				else
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
					wprintf(L" Failed\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}

				CloseHandle(hDevObj);
				break;

			case 3: // Item 3
				wprintf(L"[+] Hooking RDTSC interrupt handler...");
				dwResult = FALSE;
				hDevObj = CreateFile(
					SYS_DEVICE_NAME, 
					GENERIC_READ|GENERIC_WRITE, 
					FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				
				// Send exclusion file list to driver
				{
					CHAR **whitelist = GetExclusionFileName();
					CHAR **tempwhitelist = NULL;
					DWORD count = 0;
					tempwhitelist = whitelist;

					if (whitelist != NULL)
					{
						// Get total number of exclusion file names
						while (*whitelist != NULL)
						{
							count++;
							whitelist++;
						}

						// Send the total number of exclusion file names to driver
						if (count > 0)
						{
							if (!DeviceIoControl(
								hDevObj, 
								IOCTL_VMDETECTORSYS_SEND_COUNT_FN, 
								&count, sizeof(count), 
								&dwResult, sizeof(dwResult), 
								&dwBytesReturned, 
								NULL)) wprintf(L"\n[-] Failed in operation IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION when sending file name: %s. (0x%08x)\n", GetLastError(), *whitelist);
						}
						// Reset whitelist
						whitelist = tempwhitelist;

						// Send whitelist file name to driver
						while (*whitelist != NULL)
						{
							if (!DeviceIoControl(
								hDevObj, 
								IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION, 
								*whitelist, strlen(*whitelist), 
								&dwResult, sizeof(dwResult),
								&dwBytesReturned, 
								NULL)) wprintf(L"\n[-] Failed in operation IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION when sending file name: %s. (0x%08x)\n", GetLastError(), *whitelist);

							whitelist++;
						}
					}
				}

				// Send RDTSC definition to VMDetectorSys
				{
					// Get RDTSC method definition from vmdetector.ini configuration file
					DWORD dwRdtscMethod = GetRdtscDefinition(1);

					// Get RDTSC desired value from vmdetector.ini configuration file
					DWORD dwRdtscValue = GetRdtscDefinition(2);

					// If not defined in the configuration file, use value in g_RDTSC_CONSTANT instead
					if (dwRdtscValue == -1)
						dwRdtscValue = g_RDTSC_CONSTANT;

					switch(dwRdtscMethod)
					{
					case 0:
						// Set RDTSC to constant value
						if (!DeviceIoControl(
							hDevObj, 
							IOCTL_RDTSCEMU_METHOD_ALWAYS_CONST, 
							&dwRdtscValue, sizeof(dwRdtscValue), 
							&dwResult, sizeof(dwResult), 
							&dwBytesReturned, 
							NULL)) wprintf(L"\n[-] Failed in operation IOCTL_RDTSCEMU_METHOD_ALWAYS_CONST. (0x%08x)\n", GetLastError());
						break;
					case 1:
						// Set RDTSC to delta value
						if (!DeviceIoControl(
							hDevObj, 
							IOCTL_RDTSCEMU_METHOD_INCREASING, 
							&dwRdtscValue, sizeof(dwRdtscValue), 
							&dwResult, sizeof(dwResult), 
							&dwBytesReturned, 
							NULL)) wprintf(L"\n[-] Failed in operation IOCTL_RDTSCEMU_METHOD_INCREASING. (0x%08x)\n", GetLastError());
						break;
					default:
						wprintf(L"\n[-] Invalid RDTSC method defined. Please check vmdetector.ini configuration file\n");
						break;
					}
				}

				// Send hook command to VMDetecctorSys
				if (!DeviceIoControl(
					hDevObj, 
					IOCTL_VMDETECTORSYS_RTDSC_HOOK, 
					NULL, 0, 
					&dwResult, sizeof(dwResult), 
					&dwBytesReturned, 
					NULL)) wprintf(L"\n[-] Failed in operation IOCTL_VMDETECTORSYS_RTDSC_HOOK. (0x%08x)\n", GetLastError());

				if (dwResult)
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
					wprintf(L" Succeeded\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}
				else
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
					wprintf(L" Failed\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}

				CloseHandle(hDevObj);
				break;

			case 4: // Item 4
				wprintf(L"[+] Patching key \"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\"...");
				dwResult = FALSE;
				hDevObj = CreateFile(
					SYS_DEVICE_NAME, 
					GENERIC_READ|GENERIC_WRITE, 
					FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (!DeviceIoControl(
					hDevObj, 
					IOCTL_VMDETECTORSYS_VMDISKREG_FIX, 
					NULL, 0, 
					&dwResult, sizeof(dwResult), 
					&dwBytesReturned, 
					NULL)) wprintf(L"\n[-] Failed in operation IOCTL_VMDETECTORSYS_VMDISKREG_FIX. (0x%08x)\n", GetLastError());
				if (dwResult)
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
					wprintf(L" Succeeded\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}
				else
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
					wprintf(L" Failed\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}

				CloseHandle(hDevObj);
				break;

			case 5: // Item 5
				wprintf(L"[+] Patching key \"SYSTEM\\CurrentControlSet\\Enum\\IDE\"...");
				dwResult = PatchVmIdeReg();

				if (dwResult)
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN|FOREGROUND_INTENSITY);
					wprintf(L" Succeeded\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}
				else
				{
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED|FOREGROUND_INTENSITY);
					wprintf(L" Failed\n");
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
				}

				CloseHandle(hDevObj);
				break;

			default:
				break;
		}
		k++;

		// We can't stop the driver as we hook TSD interrupt handler in IDT => VMDetectorSys!hookstub
		/* kd> !idt 0xd

		   Dumping IDT:

		   0d:	f4761610 VmDetectorSys!hookStub
		*/
		/*if (k >= j)
			if (!StopVmDetectorDriver())
				printf("[-] Failed to stop driver. (0x%08x)\n", GetLastError());*/
	}


	return 0;
}

BOOLEAN InstallAndStartVmDetectorDriver(WCHAR *cSysDrvPath)
{
	HANDLE hSCManager;
	HANDLE hService;


	hSCManager	= OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager == NULL) return FALSE;

	hService	= OpenService(hSCManager, SYS_SERVICE_NAME, SERVICE_ALL_ACCESS);

	if (hService) 
	{
		// Service already exist
		if (!StartService(hService, 0, NULL)) return FALSE;
	}
	else if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
	{
		// Service does not exist
		hService = CreateService(
			hSCManager,
			SYS_SERVICE_NAME,
			SYS_DISPLAY_NAME,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			cSysDrvPath,
			NULL, NULL, NULL, NULL, NULL);

		if (hService == NULL) return FALSE;

		if (!StartService(hService, 0, NULL)) return FALSE;

	}

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService);

	return TRUE;
} 

BOOLEAN StopVmDetectorDriver()
{
	HANDLE hSCManager;
	HANDLE hService;
	SERVICE_STATUS ServiceStatus;


	hSCManager	= OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager == NULL) return FALSE;

	hService	= OpenService(hSCManager, SYS_SERVICE_NAME, SERVICE_ALL_ACCESS);

	if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus)) return FALSE;

	if (!DeleteService(hService)) return FALSE;

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService);

	return TRUE;
} 

VOID SendExclusionFileNames()
{
	 
}
