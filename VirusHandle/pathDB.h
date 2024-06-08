
#ifndef PATHDB_H
#define PATHDB_H
#include <locale>
#include <codecvt>
#include <sqlite3.h> 
#include <string>
#include <iostream>
#include <vector> 
#include <windows.h>



class pathDB
{
	

public:
	std::vector<char> WideCharToMultiByte(const wchar_t* wide_str);

	pathDB();
		 
	int CreateTable();

	bool UpdateStatus(const wchar_t* path, const std::string &status);
		
	bool InsertPaths(const wchar_t* path, const wchar_t* newPath);

	std::wstring GetFileNewPath(const wchar_t* path);

	void close_DB();

	bool ExistsInDB(const wchar_t* path);
		
	~pathDB() {
		if (DB) {
			sqlite3_close(DB);
			std::cout << "Database closed successfully" << std::endl;
		}
	}
private:

	sqlite3* DB;
};

#endif // PATHDB_H
