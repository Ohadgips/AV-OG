#include <iostream>
#include <windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

bool quarantineFile(const wchar_t* filePath) {
    wchar_t quarantineDir[MAX_PATH];
    wcscpy_s(quarantineDir, MAX_PATH, L"C:\\Quarantine");
}
