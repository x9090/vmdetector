#include <stdio.h>
#include <windows.h>
#include "readconfig.h"

CHAR *g_ConfigFileName = "vmdetector.ini";

CHAR **GetExclusionFileName()
{
	FILE *fConf = NULL;
	CHAR *contents = NULL;
	CHAR szConfig[MAX_PATH] = {0};
	CHAR **procname;  
	CHAR **tempProcname;
	DWORD dwSize;
	DWORD dwFileSize;
	BOOLEAN bValid = FALSE;

	fConf = fopen(g_ConfigFileName, "r");
	if (!fConf)
		return NULL;

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

DWORD GetRdtscDefinition(int option)
{
	FILE *fConf = NULL;
	CHAR *contents = NULL;
	CHAR szConfig[MAX_PATH] = {0};
	DWORD dwRdtscDef = -1;
	DWORD dwSize;
	DWORD dwFileSize;
	BOOLEAN bValid = FALSE;

	fConf = fopen(g_ConfigFileName, "r");
	if (!fConf)
		return NULL;

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
			else if(strstr(szBuff, "rdtsc_met=") != NULL && bValid && option == 1)
			{
				CHAR *start = strrchr(szBuff, '1');

				if (start == NULL)
					start = strrchr(szBuff, '0');

				if (start != NULL)
					*(start+1) = '\0';

				dwRdtscDef = start==NULL?-1:atoi(start);
			}
			// RDTSC value definition
			else if(strstr(szBuff, "rdtsc_val=") != NULL && bValid && option == 2)
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