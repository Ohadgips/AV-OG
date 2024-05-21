#include "pathDB.h"
#include <string>
#include <sqlite3.h> 
using namespace std;

pathDB::pathDB()
{
    int res;

    res = sqlite3_open("Data/VirusPaths.db", &DB);

    if (res != SQLITE_OK) {
        cerr << "Error with the DB" << sqlite3_errmsg(DB);
        exit(-1);
    }
    else
    {
        cout << "Created / Already Exists Database Successfully!" << endl;
    }
}

void pathDB::close_DB(){
    sqlite3_close(DB);
}

int pathDB::CreateTable() {
    string sql = "CREATE TABLE IF NOT EXISTS PATHS("  \
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
            cerr << "Error creating table" << sqlite3_errmsg(DB);
            sqlite3_free(messaggeError);
        }
        else
            cout << "created table successfully!" << endl;


    }

    catch (const exception& e)
    {
        cerr << e.what();
    }

    return 0;
}

bool  pathDB::ExistsInDB(const char* path) {
    int res = 0;
    sqlite3_stmt* statement;

    const char* sql = "SELECT NEW_PATH FROM PATHS WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql, -1, &statement, 0);

    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, path, -1, SQLITE_STATIC);
    res = sqlite3_step(statement);

    if (res == SQLITE_ROW) {
        return true;
    }
    return false;

}
void pathDB::InsertPaths(const char* path, const char* newPath)
{
    //char* messaggeError;
    sqlite3_stmt* statement;

    int res = 0;
    const char* sql = "INSERT OR IGNORE INTO PATHS (ORIGINAL_PATH,NEW_PATH,STATUS) VALUES(?,?,?);";

    res = sqlite3_prepare_v2(DB, sql, -3, &statement, 0);
    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, path, -1, SQLITE_STATIC); 
    sqlite3_bind_text(statement, 2, newPath, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 3, "Quarantined", -1, SQLITE_STATIC);

    res = sqlite3_step(statement);

    if (res != SQLITE_DONE) {
        std::cerr << "Error Insert" << std::endl;
    }
    else
        std::cout << "Records created Successfully!" << std::endl;

    sqlite3_finalize(statement);
}

void pathDB::UpdateStatus(const char*path, const string &status)
{
    cout << "upadate file: "<< path << " to status: "<< status << endl;
    //char* messaggeError;
    sqlite3_stmt* statement;
    int res = 0;
    const char* sql = "UPDATE PATHS SET STATUS = ? WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql, -2, &statement, 0);
    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 2, path, -1, SQLITE_STATIC);

    res = sqlite3_step(statement);

    if (res != SQLITE_DONE) {
        std::cerr << "Error update: " << sqlite3_errmsg(DB) << std::endl;
    }
    else
        std::cout << "Records Updated Successfully!" << std::endl;

    sqlite3_finalize(statement);
}

string pathDB::GetFileNewPath(const char* path)
{
    //char* messaggeError;
    sqlite3_stmt* statement;
    string new_path;
   
    int res = 0;
    const char* sql = "SELECT NEW_PATH FROM PATHS WHERE ORIGINAL_PATH = ?;";

    res = sqlite3_prepare_v2(DB, sql, -1, &statement, 0);

    if (res != SQLITE_OK) {
        std::cerr << "Error preparing statement " << sqlite3_errmsg(DB) << std::endl;
    }
    sqlite3_bind_text(statement, 1, path, -1, SQLITE_STATIC);
    res = sqlite3_step(statement);

    if (res == SQLITE_ROW) {
        const unsigned char* result = sqlite3_column_text(statement, 0);
        std::cout << "getting path Successfully!" << std::endl;
        if (result) {
            new_path = reinterpret_cast<const char*>(result);
            std::cout << new_path << std::endl;
        }
    }
    else {
        std::cout << "error getting path" << std::endl;
    }
    sqlite3_finalize(statement);
    return new_path;
}
