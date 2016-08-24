#include <windows.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <stdio.h>
#include "chkreg.h"
#include "dbgprint.h"
#include "readconfig.h"
#include "utils.h"

#pragma warning(disable:4996)
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
	int result = ERROR_ACCESS_DENIED;

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
		goto CLEANUP;

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
		result = SetNamedSecurityInfoA(
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
			result = IncreaseProcPriviledge("SeTakeOwnershipPrivilege");

			if (result != ERROR_SUCCESS)
			{
				dbgprintfA(" (%s:%d): SeTakeOwnershipPrivilege failed\n", __FILE__, __LINE__);
				goto CLEANUP;
			}

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

	
	SetLastError(result);
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

	// Start replacing VBOX string from the registry data
	{
		char *start = strstr(szBuffer, "VBox");

		if (start != NULL)
		{
			int offset = (int)start - (int)szBuffer;

			// Replace "VBox" string
			strncpy(szBuffer + offset, "MB0X", 4);
		}
	}

	// Start replacing Oracle string from the registry data
	{
		char *start = strstr(szBuffer, "Oracle");

		if (start != NULL)
		{
			int offset = (int)start - (int)szBuffer;

			// Replace "Oracle" string
			strncpy(szBuffer + offset, "0r@cl3", 6);
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

		// Add Administrator to the specified registry key with read, write and delete permission
		AddSidAllowAccessRightToReg(szKeyStr, "Administrators", &NtAuthority, GENERIC_READ | GENERIC_WRITE);

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
		dbgprintfA(" (%s:%d): Unable to open key: 0x%x\n", __FILE__, __LINE__, retnval);
	
	return bResult;
}

/**

	Description: Helper function #5
	Purpose: Rename the registry key that contains VM string
	Params: 
	@Key		=> Registry key type
	@oldName	=> Old keyname
	@newName	=> New keyname


**/
BOOLEAN PatchRegistryKeyName(RegistryKey Key, WCHAR *wSubKey, WCHAR *oldName, WCHAR *newName)
{
	LONG retnval;
	HKEY hKey;
	HKEY RegKey;
	WCHAR wKeyStr[MAX_PATH] = { 0 };
	CHAR szKeyStr[MAX_PATH] = { 0 };
	BOOLEAN bResult = FALSE;

	switch (Key)
	{
	case HKCR:
		RegKey = HKEY_CLASSES_ROOT;
		wcscat_s(wKeyStr, MAX_PATH - 1, L"CLASSES_ROOT\\");
		break;
	case HKCC:
		RegKey = HKEY_CURRENT_CONFIG;
		wcscat_s(wKeyStr, MAX_PATH - 1, L"CURRENT_CONFIG\\");
		break;
	case HKCU:
		RegKey = HKEY_CURRENT_USER;
		wcscat_s(wKeyStr, MAX_PATH - 1, L"CURRENT_USER\\");
		break;
	case HKLM:
		RegKey = HKEY_LOCAL_MACHINE;
		wcscat_s(wKeyStr, MAX_PATH - 1, L"MACHINE\\");
		break;
	case HKU:
		RegKey = HKEY_USERS;
		wcscat_s(wKeyStr, MAX_PATH - 1, L"USERS\\");
		break;
	default:
		return bResult;
	}

	if (newName == NULL)
		return bResult;

	// TODO: Check if the oldName contains VMware string
	if ((retnval = RegOpenKeyExW(RegKey, wSubKey, 0, KEY_READ | KEY_WRITE | KEY_CREATE_SUB_KEY | DELETE, &hKey)) == ERROR_SUCCESS){
		if (RegRenameKey(hKey, oldName, newName) == ERROR_SUCCESS)
		{
			bResult = TRUE;
			RegCloseKey(hKey);
		}
		else
			RegCloseKey(hKey);
	}
	else if (retnval == ERROR_ACCESS_DENIED)
	{
		// Not allow to modify the registry key
		// Add Administrator account to the specified registry key
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

		// First form the registry key object string used by SE_REGISTERY_KEY
		wcscat_s(wKeyStr, MAX_PATH - 1, wSubKey);

		WideCharToMultiByte(CP_THREAD_ACP, WC_COMPOSITECHECK, wKeyStr, -1, szKeyStr, MAX_PATH, NULL, NULL);

		// Add Administrator to the specified registry key with read and write permission
		AddSidAllowAccessRightToReg(szKeyStr, "Administrators", &NtAuthority, GENERIC_READ | GENERIC_WRITE | DELETE);

		// Try modifying the key again
		if ((retnval = RegOpenKeyExW(RegKey, wSubKey, 0, KEY_READ | KEY_WRITE | KEY_CREATE_SUB_KEY | DELETE, &hKey)) == ERROR_SUCCESS){
			if (RegRenameKey(hKey, oldName, newName) == ERROR_SUCCESS)
			{
				bResult = TRUE;
				RegCloseKey(hKey);
			}
			else
				RegCloseKey(hKey);
		}
	}

	if (retnval != ERROR_SUCCESS)
		dbgprintfA(" (%s:%d): Unable to open key: 0x%x\n", __FILE__, __LINE__, retnval);

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

	if (szRegData == NULL)
		return bResult;

	// Prepare our registry data for comparison later
	memcpy_s(szData, sizeof(szData), szRegData, strlen(szRegData));

	// Look for VMware/VirtualBox string and patch it if found
	CharLowerBuffA(szData, strlen(szData));
	if (strstr(szData, "vmware") != NULL || strstr(szData, "virtual") != NULL || strstr(szData, "virtualbox") != NULL || strstr(szData, "vbox") != NULL || strstr(szData, "oracle") != NULL)
	{
		bResult = PatchRegistryValueData(HKLM, SubKey, Value, szRegData, type);
	}
	else
	{
		bResult = FALSE;
	}

	// Empty buffer that stores a copy of our registry data
	memset(szData, 0, MAX_PATH);

	// Free heap of registry data
	free(szRegData);

	return bResult;
}

/** 

	Description: Generic VM registry key patcher
	Purpose: Generic VM string patcher from registry based on the registry key defined in vmdetector.ini

**/
BOOLEAN VMRegPatcher(int PatchType)
{
	BOOLEAN bResult;

	switch(PatchType)
	{
	case PATCH_WMI_PCI_REGKEY:
		do{
			bResult = FALSE;
			CHAR **RegKeys = GetPatchRegKeysFromConfig();
			int index = 1;

			// Quit if no registry keys defined in vmdetector.ini config
			if (RegKeys == NULL) break;

			while (*RegKeys != NULL)
			{
				dbgprintfA(" (%s:%d): (%d)%s...", __FILE__, __LINE__, index++, *RegKeys);

				// Continue if not PCI registry key
				if (strstr(*RegKeys, "HKEY_LOCAL_MACHINE\\SYSTEM\\") == NULL || strstr(*RegKeys, "\\Enum\\PCI") == NULL) 
				{
					printf("Not supported\n");
					RegKeys++;
					continue;
				}
	
				// Otherwise start obtaining the registry data
				{
					CHAR szData[MAX_PATH] = {0};
					CHAR *szRegData=NULL;
					BOOLEAN bPatch1, bPatch2, bPatch3;
					DWORD type=0;

					// Get "Class" registry data
					szRegData = GetRegistryValueData(HKLM, *RegKeys+19, "Class", &type);

					// Continue if not Display or System (for VBOX) class
					if (szRegData == NULL || (strstr(szRegData, "Display") == NULL && strstr(szRegData, "System") == NULL))
					{
						printf("Not found\n");
						RegKeys++;
						continue;
					}

					free(szRegData);
					
					if (!(bPatch1=VMRegFindAndPatchByRegValue(HKLM, *RegKeys+19, "DeviceDesc")))
						dbgprintfA(" (%s:%d): Failed to patch PCI \"DeviceDesc\"\n", __FILE__, __LINE__);
					else
						dbgprintfA(" (%s:%d): PCI \"DeviceDesc\" patched!\n", __FILE__, __LINE__);
					if (!(bPatch2=VMRegFindAndPatchByRegValue(HKLM, *RegKeys+19, "Mfg")))
						dbgprintfA(" (%s:%d): Failed to patch PCI \"Mfg\"\n", __FILE__, __LINE__);
					else
						dbgprintfA(" (%s:%d): PCI \"Mfg\" patched!\n", __FILE__, __LINE__);
					if (!(bPatch3=VMRegFindAndPatchByRegValue(HKLM, *RegKeys+19, "Service")))
						dbgprintfA(" (%s:%d): Failed to patch PCI \"Service\"\n", __FILE__, __LINE__);
					else
						dbgprintfA(" (%s:%d): PCI \"Service\" patched!\n", __FILE__, __LINE__);

					bResult = bPatch1||bPatch2||bPatch3?TRUE:FALSE;
				}

				// Next registry key
				RegKeys++;
			}
		}while(0);

		break;
	case PATCH_WMI_DISKDRIVE_SCSI_REGKEY:
		do{
			bResult = FALSE;
			CHAR **RegKeys = GetPatchRegKeysFromConfig();
			int index = 1;

			// Quit if no registry keys defined in vmdetector.ini config
			if (RegKeys == NULL) break;

			while (*RegKeys != NULL)
			{
				dbgprintfA(" (%s:%d): (%d)%s\n", __FILE__, __LINE__, index++, *RegKeys);

				// Continue if not SCSI registry key
				if (strstr(*RegKeys, "HKEY_LOCAL_MACHINE\\SYSTEM\\") == NULL || strstr(*RegKeys, "\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S") == NULL)
				{
					RegKeys++;
					continue;
				}

				// Otherwise start obtaining the registry data
				{
					CHAR szData[MAX_PATH] = { 0 };
					CHAR *szRegData = NULL;
					CHAR *szSubKey = NULL;
					WCHAR wSubKey[MAX_PATH] = { 0 };
					BOOLEAN bPatch1, bPatch2, bPatch3, bPatch4;

					szSubKey = strstr(*RegKeys, "SYSTEM\\");

					// The "FriendlyName" should contain "VMware, VMware Virtual S SCSI Disk Device"
					if (!(bPatch1 = VMRegFindAndPatchByRegValue(HKLM, szSubKey, "FriendlyName")))
						dbgprintfA(" (%s:%d): Failed to patch SCSI \"FriendlyName\"\n", __FILE__, __LINE__);

					if (!(bPatch2 = VMRegFindAndPatchByRegValue(HKLM, szSubKey, "HardwareID")))
						dbgprintfA(" (%s:%d): Failed to patch SCSI \"HardwareID\"\n", __FILE__, __LINE__);

					// Restrict access to the target registry keys
					CHAR szScsiChildKey[MAX_PATH] = { 0 };

					strcat_s(szScsiChildKey, MAX_PATH - 1, "MACHINE\\");
					strcat_s(szScsiChildKey, MAX_PATH - 1, szSubKey);

					// Set ACL on SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S\5&1982005&0&000000 key
					if (!(bPatch3 = RestrictAccessToReg(szScsiChildKey)))
						dbgprintfA(" (%s:%d): Failed to restrict access to SCSI \"%s\" (0x%x)\n", __FILE__, __LINE__, szScsiChildKey, GetLastError());
					
					CHAR szScsiRootKey[MAX_PATH] = { 0 };
					CHAR *szTempSubKey = szSubKey;
					szSubKey = strrchr(szSubKey, '\\');
					*szSubKey = '\0';
					szSubKey = strrchr(szTempSubKey, '\\');
					*szSubKey = '\0';
					strcat_s(szScsiRootKey, MAX_PATH - 1, "MACHINE\\");
					strcat_s(szScsiRootKey, MAX_PATH - 1, szTempSubKey);

					// Set ACL on SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S key
					if (!(bPatch4 = RestrictAccessToReg(szScsiRootKey)))
						dbgprintfA(" (%s:%d): Failed to restrict access to SCSI \"%s\" (0x%x)\n", __FILE__, __LINE__, szScsiRootKey, GetLastError());

					// Finally patch the registry key that contains the VM string
					//DWORD dwLength = strlen(szSubKey);

					// TODO: Access denied to rename the key :( 
					//       Figure out how to rename the key
					//MultiByteToWideChar(CP_THREAD_ACP, MB_PRECOMPOSED, szSubKey, dwLength, wSubKey, dwLength * 2);
					/*if (!(bPatch3 = PatchRegistryKeyName(HKLM, L"SYSTEM\\CurrentControlSet\\Enum\\SCSI", L"Disk&Ven_VMware_&Prod_VMware_Virtual_S", L"Disk&Pen_VMw@re_&Prod_VMw@re_Virtu@l_S")) &&
						!(bPatch4 = PatchRegistryKeyName(HKLM, L"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Pen_VMw@re_&Prod_VMw@re_Virtu@l_S", L"5&1982005&0&000000", L"5&1234567&1&1234")))
						dbgprintfA(" (%s:%d): Failed to rename key %s\n", __FILE__, __LINE__, szSubKey);*/

					//if (!(bPatch3 = PatchRegistryKeyName(HKLM, L"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S", NULL, L"Disk&Pen_VMw@re_&Prod_VMw@re_Virtu@l_S")) &&
					//	!(bPatch4 = PatchRegistryKeyName(HKLM, L"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S", L"5&1982005&0&000000", L"5&1234567&1&1234")))
					//	dbgprintfA(" (%s:%d): Failed to rename key %s\n", __FILE__, __LINE__, szSubKey);

					bResult = bPatch1&&bPatch2&&bPatch3&&bPatch4 ? TRUE : FALSE;

				}

				// Next registry key
				RegKeys++;
			}
		} while (0);

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
			strstr(DiskName, "vbox") ||
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
		"vbox",
		NULL
	};

	/*
		Retrieving the storage device property on Windows 7
		9399f9b4 828a00eb 0015fb70 853c4e80 00000080 nt!memcpy+0x33
		9399fa04 82897bbf 016fedd8 9399fa4c 9399fa44 nt!IopCompleteRequest+0xa0
		9399fa54 87c219f9 866fed98 9399fa74 87c21a17 nt!IopfCompleteRequest+0x3b4
		9399fa60 87c21a17 866fed98 00000000 00000000 storport!RaidCompleteRequestEx+0x1c
		9399fa74 87c2fb13 866fed98 00000000 866fed98 storport!RaidCompleteRequest+0x12
		9399fa88 87c59899 85387728 00000080 9399fab4 storport!RaUnitStorageQueryDevicePropertyIoctl+0x4f
		9399fa98 87c59ddb 85387728 866fed98 87c35000 storport!RaUnitStorageQueryPropertyIoctl+0x70
		9399fab4 87c57cd0 85387728 002d1400 866fee48 storport!RaUnitDeviceControlIrp+0x186
		9399fad0 82856593 85387670 866fed98 866fee6c storport!RaDriverDeviceControlIrp+0x60					// It is a virtual driver to \Driver\LSI_SAS? !devobj 85387670
		9399fae8 882616d9 002d1400 866fed98 8594d030 nt!IofCallDriver+0x63
		9399fb6c 8824bd0a 8594d030 866fed98 866fed98 CLASSPNP!ClassDeviceControl+0x72f
		9399fb88 88260e38 8594d030 002d1400 8594dd18 disk!DiskDeviceControl+0x1ac
		9399fba4 8825f3bf 8594d030 866fed98 8594d030 CLASSPNP!ClassDeviceControlDispatch+0x48
		9399fbb8 82856593 8594d030 866fed98 866fed98 CLASSPNP!ClassGlobalDispatch+0x20
		9399fbd0 87b238a4 85a54d78 866fed98 00000000 nt!IofCallDriver+0x63
		9399fbe8 87b23152 00000000 8594de08 8594dd18 partmgr!PmFilterDeviceControl+0x23c
		9399fbfc 82856593 8594dd18 866fed98 866fed98 partmgr!PmGlobalDispatch+0x1d
		9399fc14 82a4a99f 85a54d78 866fed98 866fee50 nt!IofCallDriver+0x63
		9399fc34 82a4db71 8594dd18 85a54d78 00000000 nt!IopSynchronousServiceTail+0x1f8
		9399fcd0 82a943f4 8594dd18 866fed98 00000000 nt!IopXxxControlFile+0x6aa
		9399fd04 8285d1ea 00000118 00000000 00000000 nt!NtDeviceIoControlFile+0x2a
		9399fd04 776f70b4 00000118 00000000 00000000 nt!KiFastCallEntry+0x12a
		0015fa90 776f5864 758b989d 00000118 00000000 ntdll!KiFastSystemCallRet
		0015fa94 758b989d 00000118 00000000 00000000 ntdll!ZwDeviceIoControlFile+0xc
		0015faf4 76cda671 00000118 002d1400 0015fb54 KERNELBASE!DeviceIoControl+0xf6
		0015fb20 001e1ec1 00000118 002d1400 0015fb54 kernel32!DeviceIoControlImplementation+0x80
		0015fc74 001e3173 00000000 00000000 00000000 VmDetector!CheckStorageProperty+0xe1 [c:\users\x9090\documents\visual studio 2010\projects\vmdetector-git\vmdetector\chkreg.c @ 809]
		0015fcfc 001e7207 00000001 002a2078 002a20a8 VmDetector!wmain+0x43 [c:\users\x9090\documents\visual studio 2010\projects\vmdetector-git\vmdetector\vmdetector.c @ 25]
		0015fd44 76ce3c45 7ffd7000 0015fd90 777137f5 VmDetector!__tmainCRTStartup+0xfe [f:\dd\vctools\crt\crtw32\startup\crt0.c @ 255]

	*/
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
			if (strstr(szSubkey, "vmware") != NULL || strstr(szSubkey, "vbox") != NULL || strstr(szSubkey, "virtual") != NULL)
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
				if (strstr(szData, "vmware") != NULL || strstr(szData, "vbox") != NULL || strstr(szData, "virtual") != NULL)
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
	else
		dbgprintfA(" (%s:%d) Failed RestrictAccessToReg to %s... (0x%x)\n", __FILE__, __LINE__, szPartMgrKey, GetLastError());

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
	BOOLEAN bResult = FALSE, bFinalResult = FALSE;
	int index = 0;

	while (szListVideoControllerReg[index] != NULL)
	{
		memset(szIdeKey, 0, MAX_PATH);
		strcat_s(szIdeKey, MAX_PATH-1, "MACHINE\\");
		strcat_s(szIdeKey, MAX_PATH-1, szListVideoControllerReg[index]);

		// Set ACL on the registry key
		if ((bResult = RestrictAccessToReg(szIdeKey)))
			bFinalResult = TRUE;
		dbgprintfA(" (%s:%d) Restricting access to %s... %s\n", __FILE__, __LINE__, szIdeKey, ISPASSA(bResult));

		index++;
	}

	return bFinalResult;
}