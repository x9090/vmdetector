#ifndef __chkcpucores_h__
#define __chkcpucores_h__
#endif

/* ============================= */
/* Global variables              */
/* ============================= */
// fatal error LNK1169: one or more multiply defined symbols found
// NOTE: Make sure it is not initialized
extern int g_NumberOfProcessors;

//////////////////////////////////////////////////////////////////////////
// Function prototype
//////////////////////////////////////////////////////////////////////////
BOOLEAN CheckCPUCores();