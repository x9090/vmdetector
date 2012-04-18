#include <windows.h>
#include <string.h>


typedef struct _cpuid_t
{
	unsigned int id0;
	unsigned int id1;
	unsigned int id2;
	unsigned int id3;
}CPUID, *PCPUID;

BOOLEAN CheckCPUID()
{
	CPUID id;
	char strCPUID_temp[13] = {0};
	CHAR cVmwareVmware[13] = "VMwareVMware";
	unsigned int *sig32 = (unsigned int *)strCPUID_temp;


#if defined WIN32

	#if defined _WIN64
		// Windows Platform x64
		__cpuid((int *)&id, 0);
		strncpy(strCPUID_temp, (char*)(&id.id1), 4);
		strncpy(strCPUID_temp+4, (char*)(&id.id3), 4);
		strncpy(strCPUID_temp+8, (char*)(&id.id2), 4);

	#else
		// Windows Platform x86
	__asm{		 
			//Execute CPUID with EAX = 0 to get the CPU producer
			xor eax, eax
			cpuid
			
			//MOV EBX to EAX and get the characters one by one by using shift out right bitwise operation.
			mov eax, ebx
			mov strCPUID_temp, al
			mov strCPUID_temp[1], ah
			shr eax, 16
			mov strCPUID_temp[2], al
			mov strCPUID_temp[3], ah
			//Get the second part the same way but these values are stored in EDX
			mov eax, edx
			mov strCPUID_temp[4], al
			mov strCPUID_temp[5], ah
			shr eax, 16
			mov strCPUID_temp[6], al
			mov strCPUID_temp[7], ah
			//Get the third part
			mov eax, ecx
			mov strCPUID_temp[8], al
			mov strCPUID_temp[9], ah
			shr eax, 16
			mov strCPUID_temp[10], al
			mov strCPUID_temp[11], ah
			mov strCPUID_temp[12], 00
	}

	#endif
#elif defined(__i386__)
	asm volatile ("	xor %%eax, %%eax;		\
				  pushl %%ebx;			\
				  cpuid;					\
				  movl %%ebx, %%eax;		\
				  popl %%ebx"
				  : "=a" (sig32[0]), "=c" (sig32[2]), "=d" (sig32[1])
				  );
#elif defined(__x86_64__)
	asm volatile ("	xor %%eax, %%eax;	\
				  pushq %%rbx;			\
				  cpuid;				\
				  movl %%ebx, %%eax;	\
				  popq %%rbx"
				  : "=a" (sig32[0]), "=c" (sig32[2]), "=d" (sig32[1])
				  );
#endif
	strCPUID_temp[12] = 0;
	
	if (strcmp(cVmwareVmware, strCPUID_temp) == 0)
		return TRUE;

	return FALSE;
}

BOOLEAN CheckHyperV()
{
	CHAR cVmwareVmware[13] = "VMwareVMware";
	CHAR strVendorId[13] = {0};
	int *varEbx, *varEcx, *varEdx = NULL;
	int result = FALSE;

	__asm{
		pushad
		mov eax, 1
		mov ebx, 0
		mov ecx, 0
		mov edx, 0
		// Get bit 31 of ecx
		cpuid
		cmp ecx, 0
		jz not_hypervisor_bit_set
		mov eax, 80000000h
		test ecx, eax
		jz not_hypervisor_bit_set
		mov eax, 40000000h
		// Testing the CPUID hypervisor present bit 
		cpuid
		cmp ebx, 0
		jnz hypervisor_bit_set
not_hypervisor_bit_set:
		popad
		xor eax, eax
		leave
		ret
hypervisor_bit_set:
		mov eax, ebx
		mov strVendorId, al
		mov strVendorId[1], ah
		shr eax, 16
		mov strVendorId[2], al
		mov strVendorId[3], ah
		mov eax, ecx
		mov strVendorId[4], al
		mov strVendorId[5], ah
		shr eax, 16
		mov strVendorId[6], al
		mov strVendorId[7], ah
		mov eax, edx
		mov strVendorId[8], al
		mov strVendorId[9], ah
		shr eax, 16
		mov strVendorId[10], al
		mov strVendorId[11], ah
		mov strVendorId[12], 0
		popad
	}

	if (strcmp(strVendorId, cVmwareVmware) == 0)
		result = TRUE;

	return result;
}