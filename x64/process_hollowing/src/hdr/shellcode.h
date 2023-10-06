#include <winternl.h>

// NtQueryInformationProcess
typedef NTSTATUS(WINAPI* NTQUERYINFOPROC64)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG_PTR       ReturnLength
	);

// ur shellcode here
unsigned char rawData[270336] = {

};