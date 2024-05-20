#include "VirusHandle.h"
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;

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
extern "C" {
    VIRUS_HANDLE_API void quarantinefile(const char* filePath) {

        wstring widepath = stringToWChar(string(filePath));
        LPWSTR LPwidepath = const_cast<LPWSTR>(widepath.c_str());

        wchar_t quarantineDir[MAX_PATH];
        wcscpy_s(quarantineDir, MAX_PATH, L"Quarantine");

        // creating the quarantine dir if not exists
        if (!CreateDirectory(quarantineDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            std::wcerr << L"Error creating quarantine directory. Error code: " << GetLastError() << std::endl;
        }
        //if (AccessQuarantineFolder()) {
        wchar_t fileName[MAX_PATH];
        wcscpy_s(fileName, MAX_PATH, PathFindFileName(LPwidepath));

        // create path of the quarantined file
        wchar_t quarantinedFilePath[MAX_PATH];
        PathCombine(quarantinedFilePath, quarantineDir, fileName);

        if (!MoveFile(LPwidepath, quarantinedFilePath)) {
            wcout << L"Error moving file to quarantine." << endl;
        }


        wstring np(quarantinedFilePath);
        string new_path(np.begin(), np.end());
        fs::path new_relativePath(new_path);
        fs::path new_fullPath = fs::absolute(new_relativePath);

        //update database and insert new file data
        pathDB Database = pathDB();
        Database.CreateTable();

        if (!Database.ExistsInDB(filePath))
            Database.InsertPaths(filePath, new_fullPath.string().c_str());
        else
            Database.UpdateStatus(filePath, "Quarantined");

        wcout << L" File quarantined successfully: " << quarantinedFilePath << endl;
        Database.close_DB();
    }





    VIRUS_HANDLE_API void deletefile(const char* filepath)
    {
        pathDB Database = pathDB();
        string new_path = Database.GetFileNewPath(filepath);

        // deletes the file if it exists
        int result = remove(new_path.c_str());

        // check if file has been deleted successfully
        if (result != 0) {
            cerr << "File not deleted";
        }
        else {
            Database.UpdateStatus(string(filepath), "Deleted");
            cout << "File deleted successfully";
        }
        Database.close_DB();

    }

    VIRUS_HANDLE_API void restorefile(const char* filepath)
    {
        pathDB Database = pathDB();
        string new_path = Database.GetFileNewPath(filepath);

        // deletes the file if it exists
        FILE* quarantinedFile = nullptr;
        errno_t err = fopen_s(&quarantinedFile, new_path.c_str(), "rb");
        if (err != 0) {
            std::cerr << "Error opening quarantined file: " << new_path << std::endl;
            return;
        }

        FILE* restoreFile = nullptr;
        err = fopen_s(&restoreFile, filepath, "wb");
        if (err != 0) {
            std::cerr << "Error opening quarantined file: " << new_path << std::endl;
            return;
        }

        char buffer[1024];
        size_t bytesRead;
        while ((bytesRead = fread(buffer, 1, sizeof(buffer), quarantinedFile)) > 0) {
            fwrite(buffer, 1, bytesRead, restoreFile);
        }

        fclose(quarantinedFile);
        fclose(restoreFile);

        remove(new_path.c_str());
        Database.UpdateStatus(filepath, "Restored");
        Database.close_DB();

    }
}

/*
int main()
{
    const char* str = "C:\\Users\\USER\\Downloads\\1555.jpg";
    //quarantinefile(str);
    //restorefile(str);
    deletefile(str);
    
}*/

