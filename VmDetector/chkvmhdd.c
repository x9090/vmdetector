#include <windows.h>

//////////////////////////////////////////////////////////////////////////
// Enum definitions
//////////////////////////////////////////////////////////////////////////
typedef enum RegistryKey_t{
	HKCR=0,
	HKCC,
	HKCU,
	HKLM,
	HKU
}RegistryKey;

CHAR *GetRegistryValueData(RegistryKey Key, CHAR *SubKey, CHAR *Value, DWORD *type)
{
	HKEY hKey;
	HKEY RegKey;
	DWORD ValDataType;
	CHAR *szBuffer;
	unsigned long Size;

	szBuffer = malloc(MAX_PATH);
	Size = sizeof(szBuffer) - 1;

	switch (Key)
	{
		case HKCR:
			RegKey = HKEY_CLASSES_ROOT;
			break;
		case HKCC:
			RegKey = HKEY_CURRENT_CONFIG;
			break;
		case HKCU:
			RegKey = HKEY_CURRENT_USER;
			break;
		case HKLM:
			RegKey = HKEY_LOCAL_MACHINE;
			break;
		case HKU:
			RegKey = HKEY_USERS;
			break;
		default:
			return NULL;
	}

	if (Value == NULL)
		return NULL;

	if(RegOpenKeyExA(RegKey, SubKey, 0, KEY_READ, &hKey )==ERROR_SUCCESS){
		if (RegQueryValueExA(hKey, Value, NULL, &ValDataType, (unsigned char *)szBuffer, &Size) == ERROR_MORE_DATA)
		{
			szBuffer = realloc(szBuffer, Size);
			RegQueryValueExA(hKey, Value, NULL, &ValDataType, (unsigned char *)szBuffer, &Size);
			RegCloseKey(hKey);
		}
		else
			RegCloseKey(hKey);
	}

	if (szBuffer[0] != '\0')
	{
		*type = ValDataType;
		return szBuffer;
	}
	else
		return NULL;

}

BOOL CheckStorageProperty()
{
	HANDLE hPhysicalDrv = NULL;
	int j = 0,k = 0;
	CHAR szModel[128],szBuffer[128];
	CHAR *szDrives[] = { 
		"qemu",
		"virtual",
		"vmware",
		NULL
	};

	hPhysicalDrv = CreateFile (L"\\\\.\\PhysicalDrive0", 0,FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,OPEN_EXISTING, 0, NULL);
	if (hPhysicalDrv != INVALID_HANDLE_VALUE)
	{
		STORAGE_PROPERTY_QUERY query;
		DWORD cbBytesReturned = 0;
		memset ((void *) & query, 0, sizeof (query));
		query.PropertyId = StorageDeviceProperty;
		memset (szBuffer, 0, sizeof (szBuffer));
		memset (szModel, 0, sizeof (szModel));
		if (DeviceIoControl(
			hPhysicalDrv, 
			IOCTL_STORAGE_QUERY_PROPERTY,
			&query,
			sizeof(query),
			&szBuffer,
			sizeof(szBuffer),
			&cbBytesReturned, 
			NULL)){ 
				STORAGE_DEVICE_DESCRIPTOR *descrip = (STORAGE_DEVICE_DESCRIPTOR*)&szBuffer;
				int pos = descrip->ProductIdOffset;
				int m = 0;
				int g;
				int i;
				for(g = pos;szBuffer[g] != '\0';g++){
					szModel[m++] = szBuffer[g];
				}
				CharLowerBuffA(szModel,strlen(szModel));
				for (i = 0; i < (sizeof(szDrives)/sizeof(LPSTR)) - 1; i++ ) {
					if (szDrives[i][0] != 0) {
						if(strstr(szModel,szDrives[i]))
							return TRUE;
					}
				}
		}
		CloseHandle (hPhysicalDrv);
	}
	return FALSE;
}


BOOLEAN CheckVmIdeReg()
{
	CHAR *cValueData[] = {0};

	return TRUE;
}

BOOLEAN CheckVmDiskReg()
{	
	CHAR *DiskName=NULL;
	DWORD type=0;

	DiskName = GetRegistryValueData(HKLM, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0", &type);
	
	if (DiskName != NULL && type == REG_SZ)
	{
		CharLowerBuffA(DiskName,strlen(DiskName));
		if (strstr(DiskName, "vmware") ||
			strstr(DiskName, "virtual"))
		{
			free(DiskName);
			return TRUE;
		}
	}
	free(DiskName);
	return FALSE;
}