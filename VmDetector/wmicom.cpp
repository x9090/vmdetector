#include <comdef.h>
#include <Wbemidl.h>
#include "wmicom.h"
#include "dbgprint.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma warning(disable:4996)		// Disable warning C4996: '_wcslwr'


//////////////////////////////////////////////////////////////////////////
// Global COM variables
//////////////////////////////////////////////////////////////////////////
IWbemServices *g_pSvc = NULL;
IWbemLocator  *g_pLoc = NULL;

//////////////////////////////////////////////////////////////////////////
// Windows Management Instrumentation (WMI) with C/C++
// Ref: http://msdn.microsoft.com/en-us/library/aa390423%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////

BOOLEAN WmiCheckInit()
{
	BOOLEAN result = FALSE;
	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------
	hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
	if (FAILED(hres))
	{
		dbgprintfW(L"Failed to initialize COM library. (0x%08x)\n", hres);
		return result;           
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------
	// Note: If you are using Windows 2000, you need to specify -
	// the default authentication credentials for a user by using
	// a SOLE_AUTHENTICATION_LIST structure in the pAuthList ----
	// parameter of CoInitializeSecurity ------------------------

	hres =  CoInitializeSecurity(
			NULL, 
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
			RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities 
			NULL                         // Reserved
			);


	if (FAILED(hres))
	{
		dbgprintfW(L"Failed to initialize security. (0x%08x)\n", hres);
		CoUninitialize();
		return result;
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	hres = CoCreateInstance(
		CLSID_WbemLocator,             
		0, 
		CLSCTX_INPROC_SERVER, 
		IID_IWbemLocator, (LPVOID *) &g_pLoc);

	if (FAILED(hres))
	{
		dbgprintfW(L"Failed to create IWbemLocator object.(0x%08x)\n", hres);
		CoUninitialize();
		return result;
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	hres = g_pLoc->ConnectServer(
			_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
			NULL,                    // User name. NULL = current user
			NULL,                    // User password. NULL = current
			0,                       // Locale. NULL indicates current
			NULL,                    // Security flags.
			0,                       // Authority (for example, Kerberos)
			0,                       // Context object 
			&g_pSvc				     // pointer to IWbemServices proxy
			);

	if (FAILED(hres))
	{
		dbgprintfW(L"Could not connect (0x%08x)\n", hres);
		g_pLoc->Release();     
		CoUninitialize();
		return result;                // Program has failed.
	}

	dbgprintfW(L"Connected to ROOT\\CIMV2 WMI namespace\n");

	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
			g_pSvc,                        // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
			NULL,                        // Server principal name 
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities 
			);

	if (FAILED(hres))
	{
		dbgprintfW(L"Could not set proxy blanket (0x%08x)\n", hres);
		return result;
	}

	// Step 6: --------------------------------------------------
	// This onwards, specific WMI query will be sent  -----------
	// ...
	// ...
	
	// Initialization successful
	result = true;

	return result;
}

BOOLEAN WmiCheckWin32BIOSInfo()
{
	BOOLEAN result = FALSE;
	HRESULT hres;

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = g_pSvc->ExecQuery(
		bstr_t("WQL"), 
		bstr_t("SELECT * FROM Win32_BIOS"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		dbgprintfW(L"WMI query failed (0x%08x)\n", hres);
		return result;
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			dbgprintfW(L"No instance found\n");
			return result;
		}

		VARIANT vtSerialNumber;

		memset(&vtSerialNumber, 0, sizeof(VARIANT));

		// Get the value of property that may contain Vmware/Virtual string
		hr = pclsObj->Get(L"SerialNumber", 0, &vtSerialNumber, 0, 0);
		{
			wchar_t serialNumber[256] = {0};

			BOOLEAN bSerialNumber = FALSE;

			if (vtSerialNumber.pcVal != NULL)
			{
				wsprintf(serialNumber, L"%s", vtSerialNumber.pcVal);
				dbgprintfW(L"\nSerialNumber: %s\n", vtSerialNumber.bstrVal);
				if(wcsstr(_wcslwr(serialNumber), L"virtual") != NULL || wcsstr(serialNumber, L"vmware") != NULL)
					bSerialNumber = TRUE;
			}
			else
				dbgprintfW(L"\nSerialNumber: <empty>\n");

			result = bSerialNumber?TRUE:FALSE;
		}

		VariantClear(&vtSerialNumber);

		// We found vmware/virtual related string, no need to do further query
		if (result)
			break;

		pclsObj->Release();
	}

	// Cleanup
	// ========
	pEnumerator->Release();
	pclsObj->Release();

	return result;
}

BOOLEAN WmiCheckWin32BaseBoard()
{
	BOOLEAN result = FALSE;
	HRESULT hres;

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = g_pSvc->ExecQuery(
		bstr_t("WQL"), 
		bstr_t("SELECT * FROM Win32_BaseBoard"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		dbgprintfW(L"WMI query failed (0x%08x)\n", hres);
		return result;
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			dbgprintfW(L"No instance found\n");
			return result;
		}

		VARIANT vtProduct;

		memset(&vtProduct, 0, sizeof(VARIANT));

		// Get the value of property that may contain Vmware/Virtual string
		hr = pclsObj->Get(L"Product", 0, &vtProduct, 0, 0);
		{
			wchar_t Product[256] = {0};

			BOOLEAN bProduct = FALSE;

			if (vtProduct.pcVal != NULL)
			{
				wsprintf(Product, L"%s", vtProduct.pcVal);
				dbgprintfW(L"\nProduct: %s\n", vtProduct.bstrVal);
				if(wcsstr(_wcslwr(Product), L"440bx desktop reference platform") != NULL)
					bProduct = TRUE;
			}
			else
				dbgprintfW(L"\nProduct: <empty>\n");

			result = bProduct?TRUE:FALSE;
		}

		VariantClear(&vtProduct);

		// We found vmware/virtual related string, no need to do further query
		if (result)
			break;

		pclsObj->Release();
	}

	// Cleanup
	// ========
	pEnumerator->Release();
	pclsObj->Release();

	return result;
}

BOOLEAN WmiCheckWin32Drives()
{
	BOOLEAN result = FALSE;
	HRESULT hres;

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = g_pSvc->ExecQuery(
		bstr_t("WQL"), 
		bstr_t("SELECT * FROM Win32_DiskDrive"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		dbgprintfW(L"WMI query failed (0x%08x)\n", hres);
		return result;
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			dbgprintfW(L"No instance found\n");
			return result;
		}

		VARIANT vtCaptionProp;
		VARIANT vtModelProp;
		VARIANT vtPnPDevIdProp;

		memset(&vtCaptionProp, 0, sizeof(VARIANT));
		memset(&vtModelProp, 0, sizeof(VARIANT));
		memset(&vtPnPDevIdProp, 0, sizeof(VARIANT));

		// Get the value of property that may contain Vmware/Virtual string
		hr = pclsObj->Get(L"Caption", 0, &vtCaptionProp, 0, 0);
		hr = pclsObj->Get(L"Model", 0, &vtModelProp, 0, 0);
		hr = pclsObj->Get(L"PNPDeviceID", 0, &vtPnPDevIdProp, 0, 0);
		{
			wchar_t devpropid[256] = {0};
			wchar_t caption[256] = {0};
			wchar_t model[256] = {0};
			BOOLEAN bCaption = FALSE, bModel = FALSE, bPnpDevId = FALSE;

			if (vtCaptionProp.pcVal != NULL)
			{
				wsprintf(caption, L"%s", vtCaptionProp.pcVal);
				dbgprintfW(L"Caption: %s\n", vtCaptionProp.bstrVal);
				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bCaption = TRUE;
			}
			else
				dbgprintfW(L"Caption: <empty>\n");

			if (vtModelProp.pcVal != NULL)
			{
				wsprintf(model, L"%s", vtModelProp.bstrVal);
				dbgprintfW(L"Model: %s\n", vtModelProp.bstrVal);

				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bModel = TRUE;
			}
			else
				dbgprintfW(L"Model: <empty>\n");

			if (vtPnPDevIdProp.bstrVal != NULL)
			{
				wsprintf(devpropid, L"%s", vtPnPDevIdProp.bstrVal);
				dbgprintfW(L"PNPDeviceID: %s\n", vtPnPDevIdProp.bstrVal);
				
				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bPnpDevId = TRUE;
			}
			else
				dbgprintfW(L"PNPDeviceID: <empty>\n");
			
			result = (bCaption||bModel||bPnpDevId)?TRUE:FALSE;
		}
		
		VariantClear(&vtCaptionProp);
		VariantClear(&vtModelProp);
		VariantClear(&vtPnPDevIdProp);

		// We found vmware/virtual related string, no need to do further query
		if (result)
			break;

		pclsObj->Release();
	}

	// Cleanup
	// ========
	pEnumerator->Release();
	pclsObj->Release();

	return result;
}

BOOLEAN WmiCheckWin32CDROMDrive()
{
	BOOLEAN result = FALSE;
	HRESULT hres;

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = g_pSvc->ExecQuery(
		bstr_t("WQL"), 
		bstr_t("SELECT * FROM Win32_CDROMDrive"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		dbgprintfW(L"WMI query failed (0x%08x)\n", hres);
		return result;
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj;
	ULONG uReturn = 0;
	
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			dbgprintfW(L"No instance found\n");
			return result;
		}

		VARIANT vtCaptionProp;
		VARIANT vtNameProp;
		VARIANT vtPnPDevIdProp;

		memset(&vtCaptionProp, 0, sizeof(VARIANT));
		memset(&vtNameProp, 0, sizeof(VARIANT));
		memset(&vtPnPDevIdProp, 0, sizeof(VARIANT));
		
		// Get the value of property that may contain Vmware/Virtual string
		hr = pclsObj->Get(L"Caption", 0, &vtCaptionProp, 0, 0);
		hr = pclsObj->Get(L"Name", 0, &vtNameProp, 0, 0);
		hr = pclsObj->Get(L"PNPDeviceID", 0, &vtPnPDevIdProp, 0, 0);
		{
			wchar_t devpropid[256] = {0};
			wchar_t caption[256] = {0};
			wchar_t name[256] = {0};
			BOOLEAN bCaption = FALSE, bName = FALSE, bPnpDevId = FALSE;

			if (vtCaptionProp.pcVal != NULL)
			{
				wsprintf(caption, L"%s", vtCaptionProp.pcVal);
				dbgprintfW(L"Caption: %s\n", vtCaptionProp.bstrVal);
				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bCaption = TRUE;
			}
			else
				dbgprintfW(L"Caption: <empty>\n");

			if (vtNameProp.pcVal != NULL)
			{
				wsprintf(name, L"%s", vtNameProp.bstrVal);
				dbgprintfW(L"Name: %s\n", vtNameProp.bstrVal);

				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bName = TRUE;
			}
			else
				dbgprintfW(L"Name: <empty>\n");

			if (vtPnPDevIdProp.bstrVal != NULL)
			{
				wsprintf(devpropid, L"%s", vtPnPDevIdProp.bstrVal);
				dbgprintfW(L"PNPDeviceID: %s\n", vtPnPDevIdProp.bstrVal);

				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bPnpDevId = TRUE;
			}
			else
				dbgprintfW(L"PNPDeviceID: <empty>\n");

			result = (bCaption||bName||bPnpDevId)?TRUE:FALSE;
		}

		VariantClear(&vtCaptionProp);
		VariantClear(&vtNameProp);
		VariantClear(&vtPnPDevIdProp);

		// We found vmware/virtual related string, no need to do further query
		if (result)
			break;

		pclsObj->Release();
	}

	// Cleanup
	// ========
	pEnumerator->Release();
	pclsObj->Release();

	return result;
}

BOOLEAN WmiCheckWin32VideoController()
{
	BOOLEAN result = FALSE;
	HRESULT hres;

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = g_pSvc->ExecQuery(
		bstr_t("WQL"), 
		bstr_t("SELECT * FROM Win32_VideoController"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		dbgprintfW(L"WMI query failed (0x%08x)\n", hres);
		return result;
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			dbgprintfW(L"No instance found\n");
			return result;
		}

		VARIANT vtCaptionProp;

		memset(&vtCaptionProp, 0, sizeof(VARIANT));

		// Get the value of property that may contain Vmware/Virtual string
		hr = pclsObj->Get(L"Caption", 0, &vtCaptionProp, 0, 0);
		{
			wchar_t caption[256] = {0};
			BOOLEAN bCaption = FALSE;

			if (vtCaptionProp.pcVal != NULL)
			{
				wsprintf(caption, L"%s", vtCaptionProp.pcVal);
				dbgprintfW(L"Caption: %s\n", vtCaptionProp.bstrVal);
				if (wcsstr(_wcslwr(caption), L"virtual") != NULL || wcsstr(caption, L"vmware") != NULL || wcsstr(caption, L"vbox") != NULL)
					bCaption = TRUE;
			}
			else
				dbgprintfW(L"Caption: <empty>\n");

			result = (bCaption)?TRUE:FALSE;
		}

		VariantClear(&vtCaptionProp);

		// We found vmware/virtual related string, no need to do further query
		if (result)
			break;

		pclsObj->Release();
	}

	// Cleanup
	// ========
	pEnumerator->Release();
	pclsObj->Release();

	return result;
}

void WmiCleanup()
{
	__try
	{
		if(g_pLoc != NULL)
			g_pLoc->Release();
		if(g_pSvc != NULL)
			g_pSvc->Release();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		dbgprintfW(L"AV caught!\n");
	}
	CoUninitialize();
}