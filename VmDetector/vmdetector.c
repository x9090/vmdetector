#include <windows.h>
#include <stdio.h>
#include "vmdetector.h"
#include "utils.h"

int wmain(int args, WCHAR *argv[])
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
	
	// WMI initialization
	WmiCheckInit();

	/* CASE 1 */
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

	/* CASE 3 */
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

	/* CASE 4 */
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

	/* CASE 5 */
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

	/* CASE 6 */
	wprintf(L"[%d] Checking registry \"SYSTEM\\CurrentControlSet\\Services\\PartMgr\\Enum\": ", i);
	if (CheckVmPartMgrReg())
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

	/* CASE 7 */
	wprintf(L"[%d] Checking WMI Win32_DiskDrive...: ", i);
	if (WmiCheckWin32Drives())
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

	/* CASE 8 */
	wprintf(L"[%d] Checking WMI Win32_VideoController...: ", i);
	if (WmiCheckInit() && WmiCheckWin32VideoController())
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

	// WMI cleanup
	WmiCleanup();

	// At least one fixable Anti-VM tricks
	if (j > 0)		
	{
		wprintf(L"\n\nPatching \"FIXABLE\" items...\n\n");

		// Install VmDetectorSys driver
		bInstallDrv = InstallAndStartVmDetectorDriver(VMDETECTOR_SYSTEM_DRIVER_FILE);

		if (!bInstallDrv && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) 
			wprintf(L"[+] The service \"%s\" was already started and running.\n", SYS_SERVICE_NAME);
		else if (!bInstallDrv && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
			wprintf(L"[+] The service \"%s\" was already marked for deletion.\n", SYS_SERVICE_NAME);
		else if (!bInstallDrv && GetLastError() != ERROR_SUCCESS) 
		{
			wprintf(L"[-] Failed to install and load the driver \"%s\". (0x%08x)\n", SYS_DISPLAY_NAME, GetLastError());
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

			case 5: // CheckVmIdeReg failed
				wprintf(L"[+] Patching key \"SYSTEM\\CurrentControlSet\\Enum\\IDE\"...");
				dwResult = BlockAccessVmIdeReg();

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
				break;

			case 6: // CheckVmPartMgrReg failed
				wprintf(L"[+] Restrict access to key \"SYSTEM\\CurrentControlSet\\Services\\PartMgr\\Enum");
				dwResult = BlockAccessPartMgrReg();

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
				break;
			
			case 7: // WmiCheckWin32Drives failed
				wprintf(L"[+] Bypassing WMI Win32_DiskDrive for VMware. Installing WMIFilter driver (required reboot!)... ");

				// Method 1: Manual installation via INF file
				// Method 2: Refer to Ctrl2Cap client (PNP loade method)
				// Method 3: WMI filter will attach the target device at run time, use regular Win32 API service installation method
				dwResult = InstallAndStartWMIFilterDriver(VMDETECTOR_WMIFLT_DRIVER_FILE);
				
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

				if (dwResult) 
				{
					// Re-run VmDetector after reboot
					InstallVmDetectorRunOnce();

					// Reboot the machine to load wmifilter
					RebootMachine();
				}
				else
				{
					// Print error message when failed to install WMIfilter driver
					if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) 
						wprintf(L"[+] The service \"%s\" was already started and running.\n", FLT_SERVICE_NAME);
					else if (GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
						wprintf(L"[+] The service \"%s\" was already marked for deletion.\n", FLT_SERVICE_NAME);
					else if (GetLastError() != ERROR_SUCCESS) 
						wprintf(L"[-] Failed to install and load the driver \"%s\". (0x%08x)\n", FLT_DISPLAY_NAME, GetLastError());
				}
				break;

			case 8: // WmiCheckWin32VideoController failed
				{
					BOOLEAN bResult1, bResult2;

					wprintf(L"[+] Bypassing WMI Win32_VideoController for VMware... ");
					bResult1 = VMRegPatcher(PATCH_WMI_VIDEOCONTROLLER_REGKEY);
					bResult2 = BlockAccessVmPciReg();

					if (bResult1&&bResult2)
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
				}
				break;
			default:
				break;
		}
		k++;

	// We can't stop the driver as we hook TSD interrupt handler in IDT => VMDetectorSys!hookstub
	//	/* kd> !idt 0xd

	//	   Dumping IDT:

	//	   0d:	f4761610 VmDetectorSys!hookStub
	//	*/
	//	/*if (k >= j)
	//		if (!StopVmDetectorDriver())
	//			printf("[-] Failed to stop driver. (0x%08x)\n", GetLastError());*/
	}

	system("pause");
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

BOOLEAN InstallAndStartWMIFilterDriver(WCHAR *cFltDrvPath)
{
	HANDLE hSCManager;
	HANDLE hService;


	hSCManager	= OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager == NULL) return FALSE;

	hService	= OpenService(hSCManager, FLT_SERVICE_NAME, SERVICE_ALL_ACCESS);

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
			FLT_SERVICE_NAME,
			FLT_DISPLAY_NAME,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_SYSTEM_START,	// Driver loaded at Kernel initialization
			SERVICE_ERROR_NORMAL,
			cFltDrvPath,
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

BOOLEAN InstallVmDetectorRunOnce()
{
	WCHAR *szSubKeyRunOnce = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
	WCHAR *szValue = L"VmDetector";
	WCHAR szModuleName[sizeof(WCHAR)*MAX_PATH] = {0};
	BOOLEAN bResult = FALSE;
	LONG retnval;
	HKEY hKey;

	GetModuleFileNameW(NULL, szModuleName, sizeof(WCHAR)*MAX_PATH);

	if((retnval=RegOpenKeyExW(HKEY_CURRENT_USER, szSubKeyRunOnce, 0, KEY_READ|KEY_WRITE, &hKey)) == ERROR_SUCCESS){
		if (RegSetValueExW(hKey, szValue, 0, REG_SZ, (BYTE*)szModuleName, wcslen(szModuleName)*sizeof(WCHAR)) == ERROR_SUCCESS)
		{
			bResult = TRUE;
			RegCloseKey(hKey);
		}
		else
			RegCloseKey(hKey);
	}

	return bResult;
}