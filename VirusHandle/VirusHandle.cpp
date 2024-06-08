#include "VirusHandle.h"
#include <filesystem>
namespace fs = std::filesystem;

extern "C" {
    __declspec(dllexport) void quarantinefile(const wchar_t* filePath) {
        
        SetConsoleOutputCP(CP_UTF8);
        std::locale::global(std::locale("en_US.UTF-8"));
        
        LPWSTR LPwidepath = const_cast<LPWSTR>(filePath);

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
            std::wcout << L"Error moving file to quarantine..." << std::endl;
        }


        std::wstring np(quarantinedFilePath);
        std::wstring new_path(np.begin(), np.end());
        fs::path new_relativePath(new_path);
        fs::path new_fullPath = fs::absolute(new_relativePath);

        //update database and insert new file data
        pathDB Database = pathDB();
        Database.CreateTable();

        if (!Database.ExistsInDB(filePath))
            Database.InsertPaths(filePath, new_fullPath.wstring().c_str());
        else
            Database.UpdateStatus(filePath, "Quarantined");
        Database.close_DB();

        std::wcout << L" File quarantined successfully: " << quarantinedFilePath << std::endl;
    }


}

extern "C" {

    __declspec(dllexport) void deletefile(const wchar_t* filepath)
    {
        SetConsoleOutputCP(CP_UTF8);
        std::locale::global(std::locale("en_US.UTF-8"));

        std::wcout << L"File deleted: " << filepath << std::endl;
        pathDB Database = pathDB();
        std::wstring new_path = Database.GetFileNewPath(filepath);
        std::wcout << L"File deleted: " << new_path << std::endl;

        // deletes the file if it exists
        int result = fs::remove(new_path.c_str());

        // check if file has been deleted successfully
        if (result != 0) {
            std::wcerr << "File not deleted";
        }
        else {
            Database.UpdateStatus(filepath, "Deleted");
            std::wcout << "File deleted successfully";
        }
        Database.close_DB();

    }
}
extern "C" {
    __declspec(dllexport) void restorefile(const wchar_t* filepath)
    {
        SetConsoleOutputCP(CP_UTF8);
        std::locale::global(std::locale("en_US.UTF-8"));

        std::wcout << L"File restored: " << filepath << std::endl;
        pathDB Database = pathDB();
        std::wstring new_path = Database.GetFileNewPath(filepath);
        std::vector<char> multi_byte_path = Database.WideCharToMultiByte(filepath);
        std::vector<char> multi_byte_newpath = Database.WideCharToMultiByte(new_path.c_str());

        // deletes the file if it exists
        FILE* quarantinedFile = nullptr;
        errno_t err = fopen_s(&quarantinedFile, multi_byte_newpath.data(), "rb");
        if (err != 0) {
            std::wcerr << L"Error opening quarantined file: " << new_path << std::endl;
            return;
        }

        FILE* restoreFile = nullptr;
        err = fopen_s(&restoreFile, multi_byte_path.data(), "wb");
        if (err != 0) {
            std::wcerr << L"Error opening quarantined file: " << new_path << std::endl;
            fclose(quarantinedFile);
            return;
        }

        char buffer[1024];
        size_t bytesRead;
        while ((bytesRead = fread(buffer, 1, sizeof(buffer), quarantinedFile)) > 0) {
            fwrite(buffer, 1, bytesRead, restoreFile);
        }

        fclose(quarantinedFile);
        fclose(restoreFile);

        fs::remove(new_path.c_str());
        Database.UpdateStatus(filepath, "Restored");
        Database.close_DB();


    }
}

/* For Testing
int main()
{
    const wchar_t* str = L"C:\\Users\\USER\\Downloads\\מבחן\\שלום.docx";
    //quarantinefile(str);
    //restorefile(str);
    deletefile(str);
    
}
*/

