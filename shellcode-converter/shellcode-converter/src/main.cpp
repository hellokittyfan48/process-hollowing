#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <windows.h>
#include <filesystem>

std::string openFileDialog() {
    OPENFILENAME ofn;
    char szFile[260] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE) {
        return std::string(szFile);
    }
    else {
        return "";
    }
}

int main() {
    std::string executablePath = openFileDialog();

    if (executablePath.empty()) {
        std::cerr << "No file selected." << std::endl;
        return 1;
    }

    std::ifstream file(executablePath, std::ios::binary);

    if (!file) {
        std::cerr << "Couldn't open file: " << executablePath << std::endl;
        return 1;
    }

    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});

    std::ofstream outputFile("shellcode.h");

    outputFile << "unsigned char shellcode[" << buffer.size() << "] = {" << std::endl;

    for (size_t i = 0; i < buffer.size(); ++i) {
        if (i % 16 == 0) {
            outputFile << "    ";
        }

        outputFile << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);

        if (i != buffer.size() - 1) {
            outputFile << ", ";
        }

        if ((i + 1) % 16 == 0 || i == buffer.size() - 1) {
            outputFile << "\n";
        }
    }

    outputFile << "};" << std::endl;

    size_t lastSeparatorPos = executablePath.find_last_of("\\/");
    if (lastSeparatorPos != std::string::npos) {
        executablePath.erase(lastSeparatorPos);
    }

    std::cout << "Shellcode saved in " << executablePath << "\\shellcode.h\n";

    return 0;
}
