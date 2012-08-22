#ifndef __VMDETECTOR_H__
#define __VMDETECTOR_H__
#endif

#include "chkvmhdd.h"
#include "chkcpuid.h"
#include "chkrdtsc.h"

//////////////////////////////////////////////////////////////////////////
// Function prototypes
//////////////////////////////////////////////////////////////////////////
BOOLEAN InstallAndStartVmDetectorDriver(WCHAR *);
BOOLEAN StopVmDetectorDriver();