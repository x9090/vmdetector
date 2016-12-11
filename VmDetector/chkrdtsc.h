#ifndef __chkrdtsc_h__
#define __chkrdtsc_h__
#endif

static int g_RDTSC_CONSTANT = 10;

//////////////////////////////////////////////////////////////////////////
// IOCTL code definition
//////////////////////////////////////////////////////////////////////////
#define IOCTL_VMDETECTORSYS_RTDSC_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT , FILE_ANY_ACCESS)
#define IOCTL_RDTSCEMU_METHOD_ALWAYS_CONST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_RDTSCEMU_METHOD_INCREASING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_IN_DIRECT, FILE_ANY_ACCESS)


//////////////////////////////////////////////////////////////////////////
// Function prototype
//////////////////////////////////////////////////////////////////////////
BOOLEAN CheckRTDSC();
BOOLEAN CheckRDTSCHookUsingHeuristic();
BOOLEAN PassRDTSCUsingAPIHeuristic();