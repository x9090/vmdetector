#ifndef __wmicom_h__
#define __wmicom_h__
#endif

//////////////////////////////////////////////////////////////////////////
// Function prototype
//////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

/* These functions get C linkage */
void	WmiCleanup();
BOOLEAN	WmiCheckInit();
BOOLEAN WmiCheckWin32Drives();
BOOLEAN WmiCheckWin32CDROMDrive();
BOOLEAN WmiCheckWin32VideoController();
BOOLEAN WmiCheckWin32BIOSInfo();
BOOLEAN WmiCheckWin32BaseBoard();

#ifdef __cplusplus /* If this is a C++ compiler, end C linkage */
}
#endif