#ifndef __dbgprint__
#define __dbgprint__
#endif

#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define ISPASSW(x) (x?L"passed":L"failed")
#define ISPASSA(x) (x?"passed":"failed")

//////////////////////////////////////////////////////////////////////////
// Function prototype
//////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

/* These functions get C linkage */
void dbgprintfW(WCHAR *, ...);
void dbgprintfA(CHAR *, ...);

#ifdef __cplusplus /* If this is a C++ compiler, end C linkage */
}
#endif
