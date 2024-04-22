
#include <iostream>
#include <windows.h>
#include <Shlwapi.h>
#include <string>
#include <vector>
#pragma comment(lib, "Shlwapi.lib")
using namespace std;

struct QuarantinedFile {
    std::wstring originalPath;  
    std::wstring quarantinePath;  
    bool isClean; 
};

bool quarantineFile(const wchar_t* filePath) {
    wchar_t quarantineDir[MAX_PATH];
    wcscpy_s(quarantineDir, MAX_PATH, L"C:\\Quarantine");

    // creating the quarantine dir
    if (!CreateDirectory(quarantineDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        wcout << L"Error creating quarantine directory." << endl;
        return false;
    }
    wchar_t fileName[MAX_PATH];
    wcscpy_s(fileName, MAX_PATH, PathFindFileName(filePath));
    
    // create path of the quarantined file
    wchar_t quarantinedFilePath[MAX_PATH];
    PathCombine(quarantinedFilePath, quarantineDir, fileName);

    if (!MoveFile(filePath, quarantinedFilePath)) {
        wcout << L"Error moving file to quarantine." << endl;
        return false;
    }

    wcout << L"File quarantined successfully: " << quarantinedFilePath << endl;
    return true;
}

wstring stringToWChar(const std::string& str)
{
    // calculate the buffer size
    int bufferSize = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    // error 
    if (bufferSize == 0)
    {
        std::cerr << "error" << std::endl;
        return L"";
    }
    
    std::wstring wideStr(bufferSize, L'\0');

    if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wideStr[0], bufferSize) == 0)
    {
        std::cerr << "error" << std::endl;
        return L"";
    }
    
    wideStr.resize(bufferSize - 1);
    return wideStr;

}

void quarantine(string filePath)
{
    wstring wideString = stringToWChar(filePath); // Specify file path
    wcout << wideString << endl;
    
    if (quarantineFile(const_cast<LPWSTR>(wideString.c_str()))) {
        wcout << L"File quarantined successfully!" << endl;
    }
    else {
        wcout << L"Failed to quarantine file." << endl;
    }
}


int main()
{
    string str = "C:\\Users\\USER\\Downloads\\91111.png";
    quarantine(str);
}

