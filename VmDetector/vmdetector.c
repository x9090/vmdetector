#include <windows.h>
#include <stdio.h>
#include "vmdetector.h"

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
					L"\\\\.\\VmDetectorSys", 
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
				wprintf(L"[+] Patching key \"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\"...");
				dwResult = FALSE;
				hDevObj = CreateFile(
					L"\\\\.\\VmDetectorSys", 
					GENERIC_READ|GENERIC_WRITE, 
					FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (!DeviceIoControl(
					hDevObj, 
					IOCTL_VMDETECTORSYS_VMDISKREG_FIX, 
					NULL, 0, 
					&dwResult, sizeof(dwResult), 
					&dwBytesReturned, 
					NULL)) wprintf(L"\n[-] Failed in operation IOCTL_VMDETECTORSYS_VMDISKREG_FIX. (0x%08x)", GetLastError());
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

		if (k >= j)
			if (!StopVmDetectorDriver())
				printf("[-] Failed to stop driver. (0x%08x)\n", GetLastError());
	}


	return 0;
}

BOOLEAN InstallAndStartVmDetectorDriver(WCHAR *cSysDrvPath)
{
	HANDLE hSCManager;
	HANDLE hService;


	hSCManager	= OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCManager == NULL) return FALSE;

	hService	= OpenService(hSCManager, L"VmDetectorSys", SERVICE_ALL_ACCESS);

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
			L"VmDetectorSys",
			L"VMware Detector System Driver",
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

	hService	= OpenService(hSCManager, L"VmDetectorSys", SERVICE_ALL_ACCESS);

	if (!ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus)) return FALSE;

	if (!DeleteService(hService)) return FALSE;

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService);

	return TRUE;
} 
