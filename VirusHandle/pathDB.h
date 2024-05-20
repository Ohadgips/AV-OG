
#ifndef PATHDB_H
#define PATHDB_H

#include <sqlite3.h> 
#include <string>
#include <iostream>
using namespace std;
class pathDB
{
	

public:
		
	pathDB();
		 
	int CreateTable();

	void UpdateStatus(const string &path, const string &status);
		
	void InsertPaths(const char* path, const char* newPath);

	string GetFileNewPath(const char* path);

	void close_DB();

	bool ExistsInDB(const char* path);

private:

	sqlite3* DB;
};

#endif // PATHDB_H
