#include <stdio.h>
#include <windows.h>
#include "readconfig.h"
#include "dbgprint.h"

CHAR *g_ConfigFileName = "vmdetector.ini";

CHAR **GetExclusionFileName()
{
	FILE *fConf = NULL;
	CHAR *contents = NULL;
	CHAR szConfig[MAX_PATH] = {0};
	CHAR szConfigPath[MAX_PATH] = { 0 };
	CHAR szExePath[MAX_PATH] = { 0 };
	CHAR *pExePath = NULL;
	CHAR **procname;  
	CHAR **tempProcname;
	DWORD dwSize;
	DWORD dwFileSize;
	BOOLEAN bValid = FALSE;

	GetModuleFileNameA(NULL, szExePath, MAX_PATH);
	pExePath = strrchr(szExePath, '\\');
	*(pExePath+1) = '\0';
	strcpy_s(szConfigPath, MAX_PATH, szExePath);
	strcat_s(szConfigPath, MAX_PATH, g_ConfigFileName);

	fopen_s(&fConf, szConfigPath, "r");
	if (!fConf)
	{
		dbgprintfA(" (%s:%d): \"%s\" not found\n", __FILE__, __LINE__, szConfigPath);
		return NULL;
	}

	// Get file size
	dwFileSize = 0;
	dwSize = 0;
	fseek(fConf, 0, SEEK_END);
	dwFileSize = ftell(fConf);
	rewind(fConf);
	contents = (CHAR*)malloc(sizeof(char)*dwFileSize);
	memset(contents, 0, dwFileSize);
	procname = (CHAR**)malloc(sizeof(void*)*(dwFileSize/4));
	tempProcname = procname;
	memset(procname, 0, sizeof(void*)*(dwFileSize/4));
	dwSize   = fread(contents, sizeof(CHAR), dwFileSize, fConf);
	rewind(fConf);

	if (dwSize <= dwFileSize || dwSize > 0)
	{
		// Parsing the file content here
		while (fgets(szConfig, MAX_PATH, fConf) != NULL)
		{
			CHAR *szBuff = (CHAR*)malloc(strlen(szConfig));
			memset(szBuff, 0, strlen(szConfig));
			memcpy_s(szBuff, MAX_PATH, szConfig, strlen(szConfig));

			// Skip commented line
			if(strchr(szBuff, ';') == szBuff)
				continue;
			// Config file header
			else if (strstr(szBuff, "[vmdetector_conf]") != NULL)
				bValid = TRUE;
			// Whitelist definition
			else if(strstr(szBuff, "name=") != NULL && bValid)
			{
				CHAR *start = strrchr(szBuff, '=');
				CHAR *end   = strstr(szBuff, ".exe");

				if (start != NULL && end != NULL)
				{
					CHAR *tokens = strtok(szBuff, "=");
					CHAR *filename = start + 1;
					*(end+4) = '\0';
					*procname = filename;
					procname++;
				}
			}
		}
	}

	fclose(fConf);
	free(contents);
	return tempProcname;
	
}

DWORD GetRdtscDefinition(VMDET_CONFIG option)
{
	FILE *fConf = NULL;
	CHAR *contents = NULL;
	CHAR szConfig[MAX_PATH] = {0};
	DWORD dwRdtscDef = -1;
	DWORD dwSize;
	DWORD dwFileSize;
	BOOLEAN bValid = FALSE;

	fopen_s(&fConf, g_ConfigFileName, "r");
	if (!fConf)
	{
		dbgprintfA(" (%s:%d): %s not found\n", __FILE__, __LINE__, g_ConfigFileName);
		return -1;
	}

	// Get file size
	dwFileSize = 0;
	dwSize = 0;
	fseek(fConf, 0, SEEK_END);
	dwFileSize = ftell(fConf);
	rewind(fConf);
	contents = (CHAR*)malloc(sizeof(char)*dwFileSize);
	memset(contents, 0, dwFileSize);
	dwSize   = fread(contents, sizeof(CHAR), dwFileSize, fConf);
	rewind(fConf);

	if (dwSize <= dwFileSize || dwSize > 0 && option > 0)
	{
		// Parsing the file content here
		while (fgets(szConfig, MAX_PATH, fConf) != NULL)
		{
			CHAR *szBuff = (CHAR*)malloc(strlen(szConfig));
			memset(szBuff, 0, strlen(szConfig));
			memcpy_s(szBuff, MAX_PATH, szConfig, strlen(szConfig));

			// Skip commented line
			if(strchr(szBuff, ';') == szBuff)
				continue;
			// Config file header
			else if (strstr(szBuff, "[vmdetector_conf]") != NULL)
				bValid = TRUE;
			// RDTSC method definition
			else if(strstr(szBuff, "rdtsc_met=") != NULL && bValid && option == VMDET_CONFIG_RDTSC_METHOD)
			{
				CHAR *start = strrchr(szBuff, '1');

				if (start == NULL)
					start = strrchr(szBuff, '0');

				if (start != NULL)
					*(start+1) = '\0';

				dwRdtscDef = start==NULL?-1:atoi(start);
			}
			// RDTSC value definition
			else if(strstr(szBuff, "rdtsc_val=") != NULL && bValid && option == VMDET_CONFIG_RDTSC_METHOD_VAL)
			{
				CHAR *start = strrchr(szBuff, '=');
				CHAR *end   = strrchr(szBuff, '\n');

				if (start != NULL && end != NULL)
				{
					*(end) = '\0';
					
					dwRdtscDef = atoi(start+1);
				}
			}
		}
	}

	fclose(fConf);
	free(contents);
	return dwRdtscDef;
}

CHAR **GetPatchRegKeysFromConfig()
{
	FILE *fConf = NULL;
	CHAR *contents = NULL;
	CHAR szConfig[MAX_PATH] = { 0 };
	CHAR szConfigPath[MAX_PATH] = { 0 };
	CHAR szExePath[MAX_PATH] = { 0 };
	CHAR *pExePath = NULL;
	CHAR **regKeys;  
	CHAR **tempRegKeys;
	DWORD dwSize;
	DWORD dwFileSize;
	BOOLEAN bValid = FALSE;

	GetModuleFileNameA(NULL, szExePath, MAX_PATH);
	pExePath = strrchr(szExePath, '\\');
	*(pExePath+1) = '\0';
	strcpy_s(szConfigPath, MAX_PATH, szExePath);
	strcat_s(szConfigPath, MAX_PATH, g_ConfigFileName);

	fopen_s(&fConf, szConfigPath, "r");
	if (!fConf)
	{
		dbgprintfA(" (%s:%d): \"%s\" not found\n", __FILE__, __LINE__, szConfigPath);
		return NULL;
	}

	// Get file size
	dwFileSize = 0;
	dwSize = 0;
	fseek(fConf, 0, SEEK_END);
	dwFileSize = ftell(fConf);
	rewind(fConf);
	contents = (CHAR*)malloc(sizeof(char)*dwFileSize);
	memset(contents, 0, dwFileSize);
	regKeys = (CHAR**)malloc(sizeof(void*)*(dwFileSize/4));
	tempRegKeys = regKeys;
	memset(regKeys, 0, sizeof(void*)*(dwFileSize/4));
	dwSize   = fread(contents, sizeof(CHAR), dwFileSize, fConf);
	rewind(fConf);

	if (dwSize <= dwFileSize || dwSize > 0)
	{
		// Parsing the file content here
		while (fgets(szConfig, MAX_PATH, fConf) != NULL)
		{
			CHAR *szBuff = (CHAR*)malloc(strlen(szConfig)+1);
			memset(szBuff, 0, strlen(szConfig)+1);
			memcpy_s(szBuff, MAX_PATH, szConfig, strlen(szConfig));

			// Skip commented line
			if(strchr(szBuff, ';') == szBuff)
				continue;
			// Config file header
			else if (!bValid && strstr(szBuff, "[vmdetector_conf]") != NULL)
				bValid = TRUE;
			// Registry key to be patched
			else if(strstr(szBuff, "patchregkey=") != NULL && bValid)
			{
				CHAR *start = strrchr(szBuff, '=');
				CHAR *end = strrchr(szBuff, '\n');

				if (end == NULL)
					end = strstr(szBuff, "\r\n");

				if (start != NULL)
				{
					CHAR *key = start + 1;

					// If there are multiple lines, handle carriage return
					if (end != NULL)
						*(end) = '\0';

					*regKeys = key;
					regKeys++;
				}
			}
		}
	}

	fclose(fConf);
	free(contents);
	return tempRegKeys;

}