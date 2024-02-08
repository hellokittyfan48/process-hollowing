#include <fstream>
#include <cstdlib>

#include "hdr/funcs.h"

unsigned char* getPEbytes(const std::string& filename, std::streamsize& size) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return nullptr;
    }

    size = file.tellg();
    file.seekg(0, std::ios::beg);

    unsigned char* buffer = new unsigned char[size];
    if (!file.read(reinterpret_cast<char*>(buffer), size)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        delete[] buffer;
        return nullptr;
    }

    return buffer;
}

void printPlus() {
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);

    std::cout << "\n[";
    SetConsoleTextAttribute(console, 2);
    std::cout << "+";
    SetConsoleTextAttribute(console, 7);
    std::cout << "] ";
}