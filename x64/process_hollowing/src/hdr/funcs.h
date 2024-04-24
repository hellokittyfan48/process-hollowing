#pragma once

#include <iostream>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* NTQUERYINFOPROC64)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG_PTR       ReturnLength
);

void printPlus();