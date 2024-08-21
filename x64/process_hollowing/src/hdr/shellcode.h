#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <fstream>
#include <cstdlib>

typedef NTSTATUS(WINAPI* NTQUERYINFOPROC64)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG_PTR       ReturnLength
	);

unsigned char shellcode[3] = {
	0x90, 0x90, 0x90
};
