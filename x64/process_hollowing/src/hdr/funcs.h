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

void printPlus() {
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);

	std::cout << "\n[";
	SetConsoleTextAttribute(console, 2);
	std::cout << "+";
	SetConsoleTextAttribute(console, 7);
	std::cout << "] ";
}