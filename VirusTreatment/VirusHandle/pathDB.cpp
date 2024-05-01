#include "pathDB.h"
#include <string>

using namespace std;

sqlite3* pathDB::CreateDB()
{
    sqlite3* DB;
    int res;

    res = sqlite3_open("VirusPaths.db", &DB);

    if (res != SQLITE_OK) {
        cerr << "Error with the DB" << sqlite3_errmsg(DB);
        exit(-1);
    }
    else
    {
        cout << "Created / Already Exists Database Successfully!" << endl;
        return DB;
    }
    sqlite3_close(DB);
}

int pathDB::CreateTable() {
    sqlite3* DB;
    string sql = "CREATE TABLE IF NOT EXISTS PATHS("  \
        "ID  INT PRIMARY KEY    NOT NULL," \
        "ORIGNAL_PATH   TEXT    NOT NULL," \
        "NEW_PATH       TEXT    NOT NULL'"\
        "STATUS         TEXT    NOT NULL);";

    try
    {
        int res = 0;
        res = sqlite3_open("VirusPaths.db", &DB);

        char* messaggeError;
        res = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messaggeError);
        if (res != SQLITE_OK) {
            cerr << "Error creating table" << sqlite3_errmsg(DB);
            sqlite3_free(messaggeError);
        }
        else
            cout << "created table successfully!" << endl;

        sqlite3_close(DB);

    }

    catch (const exception& e)
    {
        cerr << e.what();
    }

    return 0;
}

int pathDB::InsertPaths(string path, string newPath)
{
    sqlite3* DB;
    char* messaggeError;
    sqlite3_stmt* statement;

    int res = sqlite3_open("VirusPaths.db",&DB);
    string sql = "INSERT INTO PATHS (ORIGINAL_PATH,NEW_PATH,STATUS) VALUES (?,?,?,?);";

    res = sqlite3_prepare_v2(DB, sql.c_str(), -3, &statement, 0);
    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, path.c_str(), -1, SQLITE_STATIC); 
    sqlite3_bind_text(statement, 1, newPath.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 1, "Quarantined", -1, SQLITE_STATIC);

    res = sqlite3_step(statement);

    if (res != SQLITE_OK) {
        std::cerr << "Error Insert" << std::endl;
    }
    else
        std::cout << "Records created Successfully!" << std::endl;

    sqlite3_finalize(statement);
    sqlite3_close(DB);
}

int pathDB::UpdateStatus(string path, string status)
{
    sqlite3* DB;
    char* messaggeError;
    sqlite3_stmt* statement;

    int res = sqlite3_open("VirusPaths.db", &DB);
    string sql = "UPDATE PATHS SET STATUS = ? WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql.c_str(), -2, &statement, 0);
    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 1, status.c_str(), -1, SQLITE_STATIC);

    res = sqlite3_step(statement);

    if (res != SQLITE_OK) {
        std::cerr << "Error update" << std::endl;
    }
    else
        std::cout << "Records Updated Successfully!" << std::endl;

    sqlite3_finalize(statement);
    sqlite3_close(DB);
}

string pathDB::GetFileNewPath(string path)
{
    sqlite3* DB;
    char* messaggeError;
    sqlite3_stmt* statement;
    const unsigned char* new_path;
    int res = sqlite3_open("VirusPaths.db", &DB);
    string sql = "SELECT NEW_PATH FROM PATHS WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql.c_str(), -1, &statement, 0);

    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, path.c_str(), -1, SQLITE_STATIC);
    res = sqlite3_step(statement);

    if (res == SQLITE_ROW) {
        new_path = sqlite3_column_text(statement, 0);   

    }
    else {
        std::cout << "Records created Successfully!" << std::endl;
    }
    sqlite3_finalize(statement);
    sqlite3_close(DB);
    string str_path = new_path ? reinterpret_cast<const char*>(new_path) : "";
    return(str_path);
}
