#include <windows.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <stdio.h>
#include "chkreg.h"
#include "dbgprint.h"
#include "readconfig.h"
#include "utils.h"

#define MAX_KEY_LENGTH 255

// 2 ways of modifying ACLs
// 1: Using NtSetSecurityObject, require SECURITY_DESCRIPTOR data structure
// 2: Using SetNamedSecurityInfo, a series of standard Windows API called: BuildExplicitAccessWithNameA -> SetEntriesInAcl -> SetNamedSecurityInfo
//                              , AllocateAndInitializeSid -> manually fill up EXPLICIT_ACCESS data structure using SID got previously -> SetEntriesInAcl -> SetNamedSecurityInfo
// (3): In some situation, you might not be able to set ACL and it returns ERROR_ACCESS_DENIED after calling SetNamedSecurityInfo, then you need to change the object's owner
//    : Requirements: - Increase process privilege with SeTakeOwnershipPrivilege
BOOLEAN RestrictAccessToReg(CHAR *Key)
{
	SID_IDENTIFIER_AUTHORITY SidEveryone = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	PSECURITY_DESCRIPTOR pSd;
	EXPLICIT_ACCESSA ea = {0};
	PSID pWorldSid	= NULL;
	PSID pSIDAdmin  = NULL;
	PACL paclNew	= NULL;
	PACL paclOld	= NULL;
	BOOLEAN bresult = FALSE;

	// Create a SID for the BUILTIN\Administrators group.
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pSIDAdmin)) 
		goto CLEANUP;

	// Get current ACL information from the registry
	if(GetNamedSecurityInfoA(
						Key, 
						SE_REGISTRY_KEY, 
						DACL_SECURITY_INFORMATION, NULL, NULL, 
						&paclOld, NULL, &pSd) != ERROR_SUCCESS)
		return bresult;

	// Empty explicit access data structure
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

	// Build EXPLICIT_ACCESS. Set deny read access to explicit access
	BuildExplicitAccessWithNameA(&ea, "Everyone", GENERIC_READ, DENY_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

	// Set 1 ACE to ACL
	if (SetEntriesInAclA(1, &ea, paclOld, &paclNew ) != ERROR_SUCCESS)
	{
		// Failed to create new ACL
		goto CLEANUP;
	}

	// Attach new ACL as the object's DACL
	{
		int result = SetNamedSecurityInfoA(
									Key, 
									SE_REGISTRY_KEY, 
									DACL_SECURITY_INFORMATION, NULL, NULL, 
									paclNew, NULL);
		if (result == ERROR_SUCCESS)
			bresult = TRUE;
	

		// If access denied, take ownership of the registry
		if (result == ERROR_ACCESS_DENIED)
		{
			// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
			IncreaseProcPriviledge("SeTakeOwnershipPrivilege");

			// Set the owner in the object's security descriptor.
			result = SetNamedSecurityInfoA(
				Key, 
				SE_REGISTRY_KEY, 
				OWNER_SECURITY_INFORMATION, pSIDAdmin, NULL, 
				NULL, NULL);

			if (result != ERROR_SUCCESS) 
				goto CLEANUP;

			// Try again to modify the object's DACL,
			// now that we are the owner.
			result = SetNamedSecurityInfoA(
				Key,							// name of the object
				SE_REGISTRY_KEY,				// type of object
				DACL_SECURITY_INFORMATION,		// change only the object's DACL
				NULL, NULL,						// do not change owner or group
				paclNew,                        // DACL specified
				NULL);							// do not change SACL

			if (result == ERROR_SUCCESS)
				bresult = TRUE;

		}


	}

CLEANUP:
		if (pWorldSid)
			FreeSid(pWorldSid);
		if (pSIDAdmin)
			FreeSid(pSIDAdmin);
		if (paclNew)
			LocalFree(paclNew);
		if (paclOld)
			LocalFree(paclOld);
		if (pSd)
			LocalFree(pSd);

	return bresult;
}

/** 
	Description: Helper function
	Purpose: Grant new account with specified access right to a registry key
	Params:	@Key => Registry key string
			@TrusteerName => Trusee name string
			@Sid => Security identifier of a speficied account
			@AccessPermission => Allowed access permission to be added to the speficied account (eg: GENERIC_WRITE)
**/
BOOLEAN AddSidAllowAccessRightToReg(CHAR *Key, CHAR *TrusteerName, SID_IDENTIFIER_AUTHORITY *Sid, DWORD AccessPermissions)
{
	PSECURITY_DESCRIPTOR pSd;
	EXPLICIT_ACCESSA ea = {0};
	PSID pSIDAdmin  = NULL;
	PACL paclNew	= NULL;
	PACL paclOld	= NULL;
	BOOLEAN bresult = FALSE;

	do{

		// Create a SID for the BUILTIN\Administrators group.
		if (!AllocateAndInitializeSid(Sid, 2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0,
			&pSIDAdmin)) 
			break;

		// Get current ACL information from the registry
		if(GetNamedSecurityInfoA(
			Key, 
			SE_REGISTRY_KEY, 
			DACL_SECURITY_INFORMATION, NULL, NULL, 
			&paclOld, NULL, &pSd) != ERROR_SUCCESS)
			break;

		// Empty explicit access data structure
		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

		// Build EXPLICIT_ACCESS. Set deny read access to explicit access
		BuildExplicitAccessWithNameA(&ea, TrusteerName, AccessPermissions, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

		// Set 1 ACE to ACL
		if (SetEntriesInAclA(1, &ea, paclOld, &paclNew ) != ERROR_SUCCESS)
		{
			// Failed to create new ACL
			break;
		}

		// Attach new ACL as the object's DACL
		{
			int result = SetNamedSecurityInfoA(
				Key, 
				SE_REGISTRY_KEY, 
				DACL_SECURITY_INFORMATION, NULL, NULL, 
				paclNew, NULL);
			if (result == ERROR_SUCCESS)
				bresult = TRUE;


			// If access denied, take ownership of the registry
			if (result == ERROR_ACCESS_DENIED)
			{
				// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
				IncreaseProcPriviledge("SeTakeOwnershipPrivilege");

				// Set the owner in the object's security descriptor.
				result = SetNamedSecurityInfoA(
					Key, 
					SE_REGISTRY_KEY, 
					OWNER_SECURITY_INFORMATION, pSIDAdmin, NULL, 
					NULL, NULL);

				if (result != ERROR_SUCCESS) 
					break;

				// Try again to modify the object's DACL,
				// now that we are the owner.
				result = SetNamedSecurityInfoA(
					Key,							// name of the object
					SE_REGISTRY_KEY,				// type of object
					DACL_SECURITY_INFORMATION,		// change only the object's DACL
					NULL, NULL,						// do not change owner or group
					paclNew,                        // DACL specified
					NULL);							// do not change SACL

				if (result == ERROR_SUCCESS)
					bresult = TRUE;

			}
		}
	}while (0);

	if (pSIDAdmin)
		FreeSid(pSIDAdmin);
	if (paclNew)
		LocalFree(paclNew);
	if (paclOld)
		LocalFree(paclOld);
	if (pSd)
		LocalFree(pSd);

	return bresult;
}
/** 

	Description: Helper function #1
	Purpose: Obtain registry value-data pair

**/
CHAR *GetRegistryValueData(RegistryKey Key, CHAR *SubKey, CHAR *Value, DWORD *type)
{
	HKEY hKey;
	HKEY RegKey;
	DWORD ValDataType;
	CHAR *szBuffer;
	unsigned long Size;

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

	szBuffer = (CHAR *)malloc(MAX_PATH);
	Size = sizeof(szBuffer) - 1;

	memset(szBuffer, 0, MAX_PATH);

	// ValDataType needs to be initialized
	ValDataType = 0;

	if(RegOpenKeyExA(RegKey, SubKey, 0, KEY_READ, &hKey ) == ERROR_SUCCESS){
		if (RegQueryValueExA(hKey, Value, 0, &ValDataType, (unsigned char *)szBuffer, &Size) == ERROR_MORE_DATA)
		{
			szBuffer = (char *)realloc(szBuffer, Size);
			RegQueryValueExA(hKey, Value, 0, &ValDataType, (unsigned char *)szBuffer, &Size);
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

/** 

	Description: Helper function #2
	Purpose: Obtain registry subkeys

**/
CHAR **GetRegistySubKeys(RegistryKey Key, CHAR *SubKey)
{
	HKEY hKey;
	HKEY RegKey;
	CHAR **arrPsubkeys = NULL;
	CHAR **arrPsubkeystemp = NULL;
	DWORD index;
	int result;

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

	if (SubKey == NULL)
		return NULL;

	index = 0;
	result = RegOpenKeyExA(RegKey, SubKey, 0, KEY_READ, &hKey);
	if(result == ERROR_SUCCESS)
	{
		CHAR *subkey;
		DWORD dwSubKeys;
		DWORD dwMaxKeySize;

		RegQueryInfoKeyA(RegKey, NULL, NULL, NULL, &dwSubKeys, &dwMaxKeySize, NULL, NULL, NULL, NULL, NULL, NULL);
		// dwMaxkeySize returned by RegQueryInfoKey does not include terminating null character
		dwMaxKeySize += 1;
		subkey		 = (CHAR*)malloc(dwMaxKeySize);
		arrPsubkeys	 = (CHAR**)malloc(sizeof(void*)*dwSubKeys+0x10);
		arrPsubkeystemp = arrPsubkeys;
		memset(arrPsubkeys, 0, sizeof(void*)*dwSubKeys+0x10);
		memset(subkey, 0, dwMaxKeySize);

		// First call to determine if the key size is enough
		// Otherwise, realloc subkey with MAX_PATH as the size
		result = RegEnumKeyExA(hKey, index, subkey, &dwMaxKeySize, NULL, NULL, NULL, NULL);
		if (result == ERROR_MORE_DATA)
		{
			dwMaxKeySize = MAX_KEY_LENGTH;
			subkey = (CHAR*)realloc(subkey, dwMaxKeySize);
			memset(subkey, 0, dwMaxKeySize);
		}
	
		while ((result = RegEnumKeyA(hKey, index, subkey, dwMaxKeySize)) != ERROR_NO_MORE_ITEMS && index < dwSubKeys)
		{
			*arrPsubkeys++ = subkey;
			index++;
			subkey	= (CHAR*)malloc(dwMaxKeySize);
			memset(subkey, 0, dwMaxKeySize);
		}

		// Free the last subkey that is not used
		free(subkey);	
	}

	if (hKey != NULL)
		RegCloseKey(hKey);
	if (arrPsubkeystemp != NULL)
		return arrPsubkeystemp;
	else
		return NULL;
}

/** 

	Description: Helper function #3
	Purpose: Obtain registry values-data pairs

**/
CHAR **GetRegistryValuesData(RegistryKey Key, int DataSize, CHAR *SubKey, DWORD *type)
{
	HKEY hKey;
	HKEY RegKey;
	DWORD valDatatype;
	CHAR **arrPdata = NULL;
	CHAR **arrPdatatemp = NULL;
	CHAR *szBuffer;
	CHAR *value;
	DWORD index;
	unsigned long ValSize;
	unsigned long Size;
	int result;

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

	if (SubKey == NULL)
		return NULL;

	index = 0;
	result = RegOpenKeyExA(RegKey, SubKey, 0, KEY_READ, &hKey);
	if(result == ERROR_SUCCESS)
	{
		value		 = (CHAR*)malloc(MAX_PATH);
		arrPdata	 = (CHAR**)malloc(sizeof(void*)*DataSize);
		arrPdatatemp = arrPdata;
		memset(arrPdata, 0, sizeof(void*)*DataSize);

		while (RegEnumValueA(hKey, index, value, &ValSize, NULL, NULL, NULL, NULL) != ERROR_NO_MORE_ITEMS)
		{
			szBuffer = (CHAR*)malloc(MAX_PATH);
			Size = sizeof(szBuffer) - 1;
			if (RegQueryValueExA(hKey, value, NULL, &valDatatype, (unsigned char *)szBuffer, &Size) == ERROR_MORE_DATA)
			{
				szBuffer = (CHAR*)realloc(szBuffer, Size);
				RegQueryValueExA(hKey, value, NULL, &valDatatype, (unsigned char *)szBuffer, &Size);
			}

			ValSize = MAX_PATH;
			type[index] = valDatatype;
			*arrPdata++ = szBuffer;
			index++;
		}
	}

	if (hKey != NULL)
		RegCloseKey(hKey);
	if (arrPdatatemp != NULL)
		return arrPdatatemp;
	else
		return NULL;

}
/** 

	Description: Helper function #4
	Purpose: Patch the specific registry key value that contains the VMware string
	Params: @Key => Registry key type
			@szSubKey => Registry subkey string
			@szValue => Registry key value to be searched
			@szData	=> Registry data that will be used to replace the registry key value specified in szValue
			@Type	=> Registry data type (eg: REG_SZ, REG_MUTLI_SZ)

**/
BOOLEAN PatchRegistryValueData(RegistryKey Key, CHAR *szSubKey, CHAR *szValue, CHAR *szData, DWORD Type)
{
	LONG retnval;
	HKEY hKey;
	HKEY RegKey;
	CHAR *szBuffer;
	CHAR szKeyStr[MAX_PATH] = {0};
	BOOLEAN bResult = FALSE;

	switch (Key)
	{
	case HKCR:
		RegKey = HKEY_CLASSES_ROOT;
		strcat_s(szKeyStr, MAX_PATH-1, "CLASSES_ROOT\\");
		break;
	case HKCC:
		RegKey = HKEY_CURRENT_CONFIG;
		strcat_s(szKeyStr, MAX_PATH-1, "CURRENT_CONFIG\\");
		break;
	case HKCU:
		RegKey = HKEY_CURRENT_USER;
		strcat_s(szKeyStr, MAX_PATH-1, "CURRENT_USER\\");
		break;
	case HKLM:
		RegKey = HKEY_LOCAL_MACHINE;
		strcat_s(szKeyStr, MAX_PATH-1, "MACHINE\\");
		break;
	case HKU:
		RegKey = HKEY_USERS;
		strcat_s(szKeyStr, MAX_PATH-1, "USERS\\");
		break;
	default:
		return bResult;
	}

	if (szSubKey == NULL || szValue == NULL || szData == NULL)
		return bResult;

	szBuffer = szData;

	// Note on Windows 7, the registry data contains the INF file where the metadata will be read
	{
		char *start = strstr(szBuffer, ".inf,%");
		char *end	= strstr(szBuffer, "%;");

		// Get the substring of the registry data that does not contain the INF file data
		if (start != NULL && end != NULL)
			szBuffer = end + 2; 
	}

	// Start replacing VMware string from the registry data
	{
		char *start = strstr(szBuffer, "VMware");

		if (start != NULL)
		{
			int offset = (int)start - (int)szBuffer;

			// Replace "VMware" string
			strncpy(szBuffer+offset, "VMw@re", 6);
		}
	}

	// Start replacing Virtual string from the registry data
	{
		char *start = strstr(szBuffer, "Virtual");

		if (start != NULL)
		{
			int offset = (int)start - (int)szBuffer;

			// Replace "Virtual" string
			strncpy(szBuffer+offset, "Virtu@l", 7);
		}
	}

	if((retnval=RegOpenKeyExA(RegKey, szSubKey, 0, KEY_READ|KEY_WRITE, &hKey)) == ERROR_SUCCESS){
		if (RegSetValueExA(hKey, szValue, 0, Type, (unsigned char *)szBuffer, strlen(szBuffer)) == ERROR_SUCCESS)
		{
			bResult = TRUE;
			RegCloseKey(hKey);
		}
		else
			RegCloseKey(hKey);
	}
	else if(retnval == ERROR_ACCESS_DENIED)
	{
		// Not allow to modify the registry key
		// Add Administrator account to the specified registry key
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

		// First form the registry key object string used by SE_REGISTERY_KEY
		strcat_s(szKeyStr, MAX_PATH-1, szSubKey);

		// Add Administrator to the specified registry key with read and write permission
		AddSidAllowAccessRightToReg(szKeyStr, "Administrators", &NtAuthority, GENERIC_READ|GENERIC_WRITE);

		// Try modifying the key again
		if((retnval=RegOpenKeyExA(RegKey, szSubKey, 0, KEY_READ|KEY_WRITE, &hKey)) == ERROR_SUCCESS){
			if (RegSetValueExA(hKey, szValue, 0, Type, (unsigned char *)szBuffer, strlen(szBuffer)) == ERROR_SUCCESS)
			{
				bResult = TRUE;
				RegCloseKey(hKey);
			}
			else
				RegCloseKey(hKey);
		}
	}
	
	if (retnval != ERROR_SUCCESS)
		dbgprintfA(" (%s:%d): Unable to open key: 0x%x\n", __FUNCTION__, __LINE__, retnval);
	
	return bResult;
}

/** 

	Description: Generic function that find and patch registry value that has VMware string
	Params: @Key => Registry key type
			@SubKey => Registry subkey string
			@Value => Registry key value

**/
BOOLEAN VMRegFindAndPatchByRegValue(RegistryKey Key, CHAR *SubKey, CHAR *Value)
{
	CHAR szData[MAX_PATH] = {0};
	CHAR *szRegData=NULL;
	BOOLEAN bResult = FALSE;
	DWORD type=0;

	// Get specified registry data
	szRegData = GetRegistryValueData(HKLM, SubKey, Value, &type);

	// Prepare our registry data for comparison later
	memcpy_s(szData, sizeof(szData), szRegData, strlen(szRegData));

	// Look for VMware string and patch it if found
	CharLowerBuffA(szData, strlen(szData));
	if (strstr(szData, "vmware") != NULL)
	{
		bResult = PatchRegistryValueData(HKLM, SubKey, Value, szRegData, type);
	}

	// Empty buffer that stores a copy of our registry data
	memset(szData, 0, MAX_PATH);

	// Free heap of registry data
	free(szRegData);

	return bResult;
}

/** 

	Description: Helper function #5
	Purpose: Generic VM string patcher from registry based on the registry key defined in vmdetector.ini

**/
BOOLEAN VMRegPatcher(int PatchType)
{
	BOOLEAN bResult = FALSE;

	switch(PatchType)
	{
	case PATCH_WMI_VIDEOCONTROLLER_REGKEY:
		do{
			CHAR **RegKeys = GetPatchRegKeysFromConfig();
			int index = 1;

			// Quit if no registry keys defined in vmdetector.ini config
			if (RegKeys == NULL) break;

			while (*RegKeys != NULL)
			{
				dbgprintfA(" (%s:%d): (%d)%s\n", __FUNCTION__, __LINE__, index++, *RegKeys);

				// Continue if not PCI registry key
				if (strstr(*RegKeys, "HKEY_LOCAL_MACHINE\\SYSTEM\\") == NULL && strstr(*RegKeys, "\\Enum\\PCI") == NULL) 
				{
					RegKeys++;
					continue;
				}
	
				// Otherwise start obtaining the registry data
				{
					CHAR szData[MAX_PATH] = {0};
					CHAR *szRegData=NULL;
					BOOLEAN bPatch1, bPatch2;
					DWORD type=0;

					// Get "Class" registry data
					szRegData = GetRegistryValueData(HKLM, *RegKeys+19, "Class", &type);

					// Continue if not Display class
					if (szRegData == NULL || strstr(szRegData, "Display") == NULL)
					{
						RegKeys++;
						continue;
					}

					free(szRegData);

					if (!(bPatch1=VMRegFindAndPatchByRegValue(HKLM, *RegKeys+19, "DeviceDesc")))
						dbgprintfA(" (%s:%d): Failed to patch PCI \"DeviceDesc\"\n", __FUNCTION__, __LINE__);

					if (!(bPatch2=VMRegFindAndPatchByRegValue(HKLM, *RegKeys+19, "Mfg")))
						dbgprintfA(" (%s:%d): Failed to patch PCI \"Mfg\"\n", __FUNCTION__, __LINE__);

					bResult = bPatch1&&bPatch2?TRUE:FALSE;
				}

				// Next registry key
				RegKeys++;
			}
		}while(0);

		break;
	default:
		printf("Unknown patch type\n");
		break;

	}
	return bResult; 
}
/** 

	Description: VM string checker from registry #1
	Purpose: Check VM string from VMSCSI registry 

**/
BOOLEAN CheckVmScsiReg()
{
	CHAR *cDevScsiKey[3] = {"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
							"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
							"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"};
	CHAR szDevScsiKey[MAX_PATH] = {0};
	CHAR szData[MAX_PATH] = {0};
	DWORD DataType[5] = {0}; // Maximum 5 data
	CHAR **Data;
	int i,j;
	BOOLEAN bResult = FALSE;

	for (i=0; i < 3; i++)
	{
		Data = GetRegistryValuesData(HKLM, 10, cDevScsiKey[i], &DataType[0]);

		if (Data != NULL && *Data != NULL)
		{
			strcat_s(szDevScsiKey, MAX_PATH-1, "MACHINE\\");
			strcat_s(szDevScsiKey, MAX_PATH-1, cDevScsiKey[i]);

			for (j=0; j<5&&*Data!=NULL; j++)
			{
				DWORD type = DataType[j];
				DWORD size = strlen(*Data);
				memcpy_s(szData, sizeof(szData), *Data, size);
				if (type == REG_SZ || type == REG_EXPAND_SZ)
				{
					CharLowerBuffA(szData, strlen(szData));
					if (strstr(szData, "vmware") != NULL || strstr(szData, "virtual") != NULL)
					{
						// Set ACL on cPartMgrKey 
						if (RestrictAccessToReg(szDevScsiKey))
						{
							bResult = TRUE;
							break;
						}
					}
				}
				memset(szData, 0, MAX_PATH);
				// We no longer need the data buffer that stored as a pointer in Data
				free(*Data);
				Data++;
			}
			// Free data buffer if it is not freed yet
			while (*Data != NULL) free(*Data);
		}

	}
	return bResult;
}

/** 

	Description: VM string checker from registry #2
	Purpose: Check VM string from Disk class service registry key

**/
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

/** 

	Description: VM string checker from raw disk #3
	Purpose: Check VM string from device disk model name via IOCTL_STORAGE_QUERY_PROPERTY

**/
BOOLEAN CheckStorageProperty()
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

/** 

	Description: VM string checker from registry #4
	Purpose: Check VM string from IDE registry

**/
BOOLEAN CheckVmIdeReg()
{
	CHAR *cIdeEnumKey = "SYSTEM\\CurrentControlSet\\Enum\\IDE";
	CHAR **Subkeys;
	BOOLEAN bResult = FALSE;

	Subkeys = GetRegistySubKeys(HKLM, cIdeEnumKey);

	if (Subkeys != NULL && *Subkeys != NULL)
	{
		CHAR szSubkey[MAX_PATH] = {0};

		while(Subkeys != NULL && *Subkeys != NULL)
		{
			DWORD dwSize = strlen(*Subkeys);

			memcpy_s(szSubkey, sizeof(szSubkey), *Subkeys, dwSize);
			CharLowerBuffA(szSubkey, strlen(szSubkey));
			if (strstr(szSubkey, "vmware") != NULL || strstr(szSubkey, "virtual") != NULL)
			{
				bResult = TRUE;
				break;
			}
			
			memset(szSubkey, 0, MAX_PATH);
			// We no longer need the data buffer that stored as a pointer in Data
			free(*Subkeys);
			Subkeys++;
		}
		// Free data buffer if it is not freed yet
		while (*Subkeys != NULL) 
		{
			free(*Subkeys);
			Subkeys++;
		}
	}

	return bResult;
}

/** 

	Description: VM string checker from registry #5
	Purpose: Check VM string from PartMgr registry key

**/
BOOLEAN CheckVmPartMgrReg()
{
	CHAR *cPartMgrKey = "SYSTEM\\CurrentControlSet\\Services\\PartMgr\\Enum";
	CHAR szData[MAX_PATH] = {0};
	DWORD DataType[10] = {0}; // Maximum 10 data
	CHAR **Data;
	int index;
	BOOLEAN bResult = FALSE;

	Data = GetRegistryValuesData(HKLM, 10, cPartMgrKey, &DataType[0]);

	if (Data != NULL && *Data != NULL)
	{
		for (index=0; index<10&&*Data!=NULL; index++)
		{
			DWORD type = DataType[index];
			DWORD size = strlen(*Data);
			memcpy_s(szData, sizeof(szData), *Data, size);
			if (type == REG_SZ || type == REG_EXPAND_SZ)
			{
				CharLowerBuffA(szData, strlen(szData));
				if (strstr(szData, "vmware") != NULL || strstr(szData, "virtual") != NULL)
				{
					bResult = TRUE;
					break;
				}
			}
			memset(szData, 0, MAX_PATH);
			// We no longer need the data buffer that stored as a pointer in Data
			free(*Data);
			Data++;
		}
		// Free data buffer if it is not freed yet
		while (*Data != NULL) 
		{
			free(*Data);
			Data++;
		}
	}

	return bResult;
}

/** 

	Description: ACL blocker #1
	Purpose: Block registry access to PartMgr registry

**/
BOOLEAN BlockAccessPartMgrReg()
{
	CHAR *cPartMgrKey = "SYSTEM\\CurrentControlSet\\Services\\PartMgr\\Enum";
	CHAR szPartMgrKey[MAX_PATH] = {0};
	BOOLEAN bResult = FALSE;

	strcat_s(szPartMgrKey, MAX_PATH-1, "MACHINE\\");
	strcat_s(szPartMgrKey, MAX_PATH-1, cPartMgrKey);

	// Set ACL on CurrentControlSet\Services\PartMgr\Enum key
	if (RestrictAccessToReg(szPartMgrKey))
		bResult = TRUE;

	return bResult;
}

/** 

	Description: ACL blocker #2
	Purpose: Block registry access to IDE registry

**/
BOOLEAN BlockAccessVmIdeReg()
{
	CHAR *cIdeEnumKey = "SYSTEM\\CurrentControlSet\\Enum\\IDE";
	CHAR szIdeKey[MAX_PATH] = {0};
	BOOLEAN bResult = FALSE;

	strcat_s(szIdeKey, MAX_PATH-1, "MACHINE\\");
	strcat_s(szIdeKey, MAX_PATH-1, cIdeEnumKey);

	// Set ACL on cIdeEnumKey
	if (RestrictAccessToReg(szIdeKey))
		bResult = TRUE;

	return bResult;
}

/** 

	Description: ACL blocker #3
	Purpose: Block registry access to a couple of registry keys that are related to WMI_VideoController
			 Counter WMI_VideoController
			 For the purpose of each registry key defined in the list, check wmi_call_stacks.txt


**/
BOOLEAN BlockAccessVmPciReg()
{
	CHAR *szListVideoControllerReg[] = {
										"SYSTEM\\CurrentControlSet\\Enum\\PCI", // PCI service key
										"SYSTEM\\ControlSet002\\Enum\\PCI",
										"SYSTEM\\ControlSet003\\Enum\\PCI",
										"SYSTEM\\ControlSet004\\Enum\\PCI",
										"SYSTEM\\CurrentControlSet\\Control\\Video", // Video service registry key
										"SYSTEM\\ControlSet002\\Control\\Video",
										"SYSTEM\\ControlSet003\\Control\\Video",
										"SYSTEM\\ControlSet004\\Control\\Video",
										"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}", // Video CLASS registry key
										"SYSTEM\\ControlSet002\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}",
										"SYSTEM\\ControlSet003\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}",
										"SYSTEM\\ControlSet004\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}",
										NULL
									  };
	CHAR szIdeKey[MAX_PATH] = {0};
	BOOLEAN bResult = FALSE;
	int index = 0;

	while (szListVideoControllerReg[index] != NULL)
	{
		memset(szIdeKey, 0, MAX_PATH);
		strcat_s(szIdeKey, MAX_PATH-1, "MACHINE\\");
		strcat_s(szIdeKey, MAX_PATH-1, szListVideoControllerReg[index]);

		// Set ACL on the registry key
		bResult = RestrictAccessToReg(szIdeKey);
		dbgprintfA(" (%s:%d) Restricting access to %s... %s\n", __FUNCTION__, __LINE__, szIdeKey, ISPASSA(bResult));

		index++;
	}

	return bResult;
}