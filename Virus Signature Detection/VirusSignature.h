#pragma once
#include <sqlite3.h>
#include <array>
#include <vector>
#include <string>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sqlite3.h>
#include <filesystem>
#include <algorithm>
using namespace std;
class VirusSignature
{
	private:
		vector <string> VirusSign;
		sqlite3* DB;

	public:
		struct threat {
			std::string filepathname;
			std::string threattype;
		};

		VirusSignature();

		//sqlite3* ConnectToDB();	
	
		//vector<string> SVList(sqlite3* DB);
	
		void AddToTable(sqlite3* DB, const char* str, int size, const char* name, int flevel);
	
		string ToHex(array<uint8_t, 16> result);

		string HashFileToMD5(const string& filename);

		void SpecificVirus(const char* md5hashstring, const char* filehash, vector<threat>& threats);

		void SearchInDB(const char* md5hashstring, vector<threat>& threats);

		void processFiles(const string& root_directory, vector<threat>& threats);

		vector<threat> SearchForThreat(string root_directory);

};

