#ifndef __VMDETECTOR_H__
#define __VMDETECTOR_H__
#endif

#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#include "chkreg.h"
#include "chkcpuid.h"
#include "chkrdtsc.h"
#include "chkcpucores.h"
#include "wmicom.h"
#include "readconfig.h"

#define IOCTL_VMDETECTORSYS_SEND_FN_EXCLUSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_SEND_COUNT_FN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_IN_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_VMDETECTORSYS_SCSI_FIX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)

#define VMDETECTOR_SYSTEM_DRIVER_FILE L"\\\\?\\C:\\Windows\\system32\\drivers\\VmDetectorSys.sys"
#define VMDETECTOR_WMIFLT_DRIVER_FILE L"\\\\?\\C:\\Windows\\system32\\drivers\\wmifilter.sys"

#define SYS_SERVICE_NAME L"iminnocent"
#define SYS_DISPLAY_NAME L"ImInnocent Detector Driver"
#define SYS_DEVICE_NAME L"\\\\.\\iminnocent"
#define FLT_SERVICE_NAME L"wmifilter"
#define FLT_DISPLAY_NAME L"WMI Filter Driver"

#if DEBUG
#define SYSTEM_PAUSE \
	system("pause");
#else
#define SYSTEM_PAUSE \
	__noop;
#endif
//////////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////////
CHAR *g_vmdetectorconf = "vmdetector.ini";

//////////////////////////////////////////////////////////////////////////
// Function prototypes
//////////////////////////////////////////////////////////////////////////
BOOLEAN InstallAndStartVmDetectorDriver(WCHAR *);
BOOLEAN InstallAndStartWMIFilterDriver(WCHAR *);
BOOLEAN InstallVmDetectorRunOnce();
BOOLEAN StopVmDetectorDriver();