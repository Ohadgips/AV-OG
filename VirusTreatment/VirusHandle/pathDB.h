#include <sqlite3.h> 
#include <string>
#include <iostream>

class pathDB
{
	private:
		sqlite3* DB;

	public:
		
		sqlite3* CreateDB();
		
		 int CreateTable();

		 int UpdateStatus(string path, string status);
		
		 int InsertPaths(string path, string newPath);

		 string GetFileNewPath(string path);

		
			struct QuarantinedFile {
			std::string originalPath;
			std::string quarantinePath;
			bool isClean;
		};

};

