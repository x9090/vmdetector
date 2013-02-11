#ifndef __VMDETECTOR_H__
#define __VMDETECTOR_H__
#endif

#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#include "chkvmhdd.h"
#include "chkcpuid.h"
#include "chkrdtsc.h"
#include "readconfig.h"

#define IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_SEND_COUNT_FN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_IN_DIRECT , FILE_ANY_ACCESS)

//////////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////////
CHAR *g_vmdetectorconf = "vmdetector.ini";

//////////////////////////////////////////////////////////////////////////
// Function prototypes
//////////////////////////////////////////////////////////////////////////
BOOLEAN InstallAndStartVmDetectorDriver(WCHAR *);
BOOLEAN StopVmDetectorDriver();