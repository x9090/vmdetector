#include <windows.h>
#include "utils.h"

DWORD IncreaseProcPriviledge(CHAR *szPriviledgeName)
{
	BOOL	result;
	HANDLE	hToken;
	TOKEN_PRIVILEGES token;

	token.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), 
		TOKEN_ADJUST_PRIVILEGES,
		&hToken) && 
		LookupPrivilegeValueA(NULL,
		szPriviledgeName,
		&token.Privileges[0].Luid))
	{
		token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken,
			FALSE,
			&token,
			sizeof(TOKEN_PRIVILEGES),
			NULL,
			NULL);
	}

	result = GetLastError();

	CloseHandle(hToken);

	return result;
}

VOID RebootMachine()
{
	IncreaseProcPriviledge("SeShutdownPrivilege");
	if (MessageBoxW(NULL, 
		L"The system need to restart to run WMI Filter properly. Do you want to restart now?",
		L"Confirm restart",
		MB_YESNO|MB_ICONINFORMATION) == IDYES)
	{
		ExitWindowsEx(EWX_REBOOT,
			SHTDN_REASON_FLAG_PLANNED|SHTDN_REASON_MINOR_OTHER|SHTDN_REASON_MAJOR_OPERATINGSYSTEM);
	}

	return;
}
