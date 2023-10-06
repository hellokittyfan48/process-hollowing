#include <winternl.h>

// NtQueryInformationProcess
typedef NTSTATUS(WINAPI* NTQUERYINFOPROC)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

// ur shellcode here
unsigned char rawData[] = {

}