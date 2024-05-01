
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <windows.h>
#include <Shlwapi.h>
#include <string>
#include <vector>
#include <sqlite3.h> 
#include "pathDB.h"
#pragma comment(lib, "Shlwapi.lib")
using namespace std;

struct QuarantinedFile {
    std::wstring originalPath;  
    std::wstring quarantinePath;  
    bool isClean; 
};

bool SetFolderPermissions(const wchar_t* folderPath) {
    return true;
}


/*
bool createFolder() {

    std::string quarantineFolderPath = "Quarantine";

    if (!filesystem::exists(quarantineFolderPath)) {
        if (!filesystem::create_directory(quarantineFolderPath)) {
            std::cerr << "error\n";
            return false;
        }
        
        // write a unique identifier 
        std::string lockFilePath = quarantineFolderPath + "/access_lock.txt";
        std::ofstream lockFile(lockFilePath);
        if (lockFile.is_open()) {
            lockFile << "da2541@gah&#fa23"; // the unique identifier
            lockFile.close();
            std::cout << "folder created and locked.\n";
        }
        else {
            std::cerr << "error\n";
            return false;
        }
    }
    else {
        cout << "Quarantine folder already exists.\n";
    }
    return true;
}

bool AccessQuarantineFolder() {
    string quarantineFolderPath = "Quarantine";
    string lockFilePath = quarantineFolderPath + "/access_lock.txt";
    string expectedCode = "da2541@gah&#fa23";

    if (std::filesystem::exists(lockFilePath)) {
        std::ifstream lockFile(lockFilePath);
        if (lockFile.is_open()) {
            std::string content;
            std::getline(lockFile, content);
            lockFile.close();


            if (content == expectedCode) {
                cout << "can access folder\n";
                return true; 
            }
        }
    }
    cout << "can NOT access folder\n";
    return false; 
}
*/
bool quarantineFile(const wchar_t* filePath) {


    wchar_t quarantineDir[MAX_PATH];
    wcscpy_s(quarantineDir, MAX_PATH, L"Quarantine");

    // creating the quarantine dir if not exists
    if (!CreateDirectory(quarantineDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        std::wcerr << L"Error creating quarantine directory. Error code: " << GetLastError() << std::endl;
        return false;
    }
    //if (AccessQuarantineFolder()) {
    wchar_t fileName[MAX_PATH];
    wcscpy_s(fileName, MAX_PATH, PathFindFileName(filePath));

    // create path of the quarantined file
    wchar_t quarantinedFilePath[MAX_PATH];
    PathCombine(quarantinedFilePath, quarantineDir, fileName);

    if (!MoveFile(filePath, quarantinedFilePath)) {
        wcout << L"Error moving file to quarantine." << endl;
        return false;
    }
    
    wstring ws(fileName);
    string original_path(ws.begin(), ws.end());
    
    wstring ws(quarantinedFilePath);
    string new_path(ws.begin(), ws.end());
    
    //update database and insert new file data
    pathDB Database = pathDB();
    Database.CreateDB();
    Database.CreateTable();
    Database.InsertPaths(original_path, new_path);

    wcout << L"File quarantined successfully: " << quarantinedFilePath << endl;
    return true;
    //}

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
    wstring wideString = stringToWChar(filePath);
    wcout << wideString << endl;
    
    if (quarantineFile(const_cast<LPWSTR>(wideString.c_str()))) {
        wcout << L"File quarantined successfully!" << endl;
    }
    else {
        wcout << L"Failed to quarantine file." << endl;
    }
}

void deletefile(string filepath)
{
    pathDB Database = pathDB();
    string new_path = Database.GetFileNewPath(filepath);

    // deletes the file if it exists
    int result = remove(filepath.c_str());

    // check if file has been deleted successfully
    if (result != 0) {
        cerr << "File deletion failed";
    }
    else {
        Database.UpdateStatus(filepath,"Deleted");
        cout << "File deleted successfully";
    }
}

void restoreFile(string filepath)
{
    pathDB Database = pathDB();
    string new_path = Database.GetFileNewPath(filepath);

    // deletes the file if it exists
    FILE* quarantinedFile = fopen(new_path.c_str(), "rb");;
    
    FILE* restoreFile = fopen(filepath.c_str(), "wb");

    char buffer[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), quarantinedFile)) > 0) {
        fwrite(buffer, 1, bytesRead, restoreFile);
    }

    fclose(quarantinedFile);
    fclose(restoreFile);

    remove(new_path.c_str());
    Database.UpdateStatus(filepath, "Restored");

    
}


int main()
{
    string str = "C:\\Users\\USER\\Downloads\\11.jpg";
    quarantine(str);
}

