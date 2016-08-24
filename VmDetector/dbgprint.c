#include <windows.h>
#include <stdio.h>
#include "dbgprint.h"

void dbgprintfW(WCHAR *Format, ...)
{
	va_list arg;
	WCHAR buffer[1024] = {0};

	va_start(arg, Format);
	_vsnwprintf(buffer, 1024, Format, arg);
	va_end(arg);

#ifdef _DEBUG
	// DEBUG message
	fwprintf(stdout, L"[DEBUG] %s", buffer);
#endif

	// ERROR message
	// ...
	fflush(stderr);
	fflush(stdout);
	return;
}

void dbgprintfA(CHAR *Format, ...)
{
	va_list arg;
	CHAR buffer[1024] = {0};

	va_start(arg, Format);
	_vsnprintf(buffer, 1024, Format, arg);
	va_end(arg);

#ifdef _DEBUG
	// DEBUG message
	fprintf(stdout, "%s", buffer);
#endif

	// ERROR message
	// ...
	fflush(stderr);
	fflush(stdout);
	return;
}

