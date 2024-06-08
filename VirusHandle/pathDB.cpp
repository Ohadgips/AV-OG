#include "pathDB.h"
#include <vector>
#include <sqlite3.h> 
#include <windows.h>
pathDB::pathDB()
{
    int res;
    res = sqlite3_open("Data/VirusPaths.db", &DB);

    if (res != SQLITE_OK) {
        std::cerr << "Error with the DB" << sqlite3_errmsg(DB);
        exit(-1);
    }
    else
    {
        std::cout << "Created / Already Exists Database Successfully!" << std::endl;
    }
}

void pathDB::close_DB(){
    sqlite3_close(DB);
}

int pathDB::CreateTable() {
    std::string sql = "CREATE TABLE IF NOT EXISTS PATHS("  \
        "ORIGINAL_PATH   TEXT    NOT NULL," \
        "NEW_PATH        TEXT    NOT NULL,"\
        "STATUS          TEXT    NOT NULL,"\
        "PRIMARY KEY(ORIGINAL_PATH, NEW_PATH)"\
        ");";

    try
    {
        int res = 0;
        char* messaggeError;
        res = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messaggeError);
        if (res != SQLITE_OK) {
            std::cerr << "Error creating table" << sqlite3_errmsg(DB);
            sqlite3_free(messaggeError);
        }
        else
            std::cout << "created table successfully!" << std::endl;


    }

    catch (const std::exception& e)
    {
        std::cerr << e.what();
    }

    return 0;
}

std::vector<char> pathDB::WideCharToMultiByte(const wchar_t* wide_str) {
    int num_chars = ::WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, nullptr, 0, nullptr, nullptr);
    if (num_chars == 0) {
        return {};
    }

    std::vector<char> multi_byte_str(num_chars);
    ::WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, multi_byte_str.data(), num_chars, nullptr, nullptr);
    return multi_byte_str;
}


bool pathDB::ExistsInDB(const wchar_t* path) {
    int res = 0;
    sqlite3_stmt* statement;
    std::vector<char> multi_byte_path = WideCharToMultiByte(path);

    const char* sql = "SELECT NEW_PATH FROM PATHS WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql, -1, &statement, 0);

    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, multi_byte_path.data(), -1, SQLITE_STATIC);
    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (res == SQLITE_ROW) {
        return true;
    }
    return false;


}
bool pathDB::InsertPaths(const wchar_t* path, const wchar_t* newPath)
{
    //char* messaggeError;
    sqlite3_stmt* statement;
    std::vector<char> multi_byte_path = WideCharToMultiByte(path);
    std::vector<char> multi_byte_newpath = WideCharToMultiByte(newPath);

    int res = 0;
    const char* sql = "INSERT OR IGNORE INTO PATHS (ORIGINAL_PATH,NEW_PATH,STATUS) VALUES(?,?,?);";

    res = sqlite3_prepare_v2(DB, sql, -3, &statement, 0);
    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
        return false;
    }
    sqlite3_bind_text(statement, 1, multi_byte_path.data(), -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 2, multi_byte_newpath.data(), -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 3, "Quarantined", -1, SQLITE_STATIC);

    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (res != SQLITE_DONE) {
        std::cerr << "Error Insert" << std::endl;
        return false;
    }
    else
        std::cout << "Records created Successfully!" << std::endl;
    return true;
}

bool pathDB::UpdateStatus(const wchar_t* path, const  std::string &status)
{
    std::wcout << L"upadate file: " << path << L" to status: ";
    std::cout << status << std::endl;
    //char* messaggeError;
    sqlite3_stmt* statement;
    int res = 0;
    const char* sql = "UPDATE PATHS SET STATUS = ? WHERE ORIGINAL_PATH = ?;";
    std::vector<char> multi_byte_path = WideCharToMultiByte(path);

    res = sqlite3_prepare_v2(DB, sql, -2, &statement, 0);
    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
        return false;
    }
    sqlite3_bind_text(statement, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 2, multi_byte_path.data(), -1, SQLITE_STATIC);

    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (res != SQLITE_DONE) {
        std::cerr << "Error update: " << sqlite3_errmsg(DB) << std::endl;
        return false;
    }
    else
        std::cout << "Records Updated Successfully!" << std::endl;
    return true;

}

std::wstring pathDB::GetFileNewPath(const wchar_t* path)
{
    //char* messaggeError;

    sqlite3_stmt* statement;
    std::wstring new_path;
    std::vector<char> multi_byte_path = WideCharToMultiByte(path);

    int res = 0;
    const char* sql = "SELECT NEW_PATH FROM PATHS WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql, -1, &statement, 0);

    if (res != SQLITE_OK) {
        std::wcerr << L"Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, multi_byte_path.data(), -1, SQLITE_STATIC);
    res = sqlite3_step(statement);

    if (res == SQLITE_ROW) {
        const unsigned char* result = sqlite3_column_text(statement, 0);
        std::wcout << L"getting path Successfully!" << std::endl;
        if (result) {
            int utf16_length = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(result), -1, nullptr, 0);
            if (utf16_length > 0) {
                std::vector<wchar_t> utf16_buffer(utf16_length);
                MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(result), -1, utf16_buffer.data(), utf16_length);
                new_path.assign(utf16_buffer.data());
            }

            std::wcout << L"getting path: "<< new_path << std::endl;

        }
    }
    else {
        std::cout << "error getting path" << std::endl;
    }
    sqlite3_finalize(statement);
    return new_path;
}
