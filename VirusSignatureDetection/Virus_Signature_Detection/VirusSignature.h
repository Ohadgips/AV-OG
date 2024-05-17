#ifndef VIRUSSIGNATURE_H
#define VIRUSSIGNATURE_H

#pragma once
#include <sqlite3.h>
#include <vector>
#include <string>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <iostream>
#include <array>
#include <sqlite3.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>

using namespace std;
class VirusSignature
{
	private:
		vector <string> VirusSign;
		sqlite3* DB1;
		sqlite3* DB2;

	public:
		VirusSignature(const char* db1_path,const char* db2_path);

		struct threat {
			string filepathname;
			string threattype;
			int id;
			int database;

			threat(const string& _filepathname, const string& _threattype, int _id, int _database);
		};

		//VirusSignature();

		//sqlite3* ConnectToDB(string dbname);	
	
		//vector<string> SVList(sqlite3* DB);
	
		void AddToTable(sqlite3* DB, const char* str, int size, const char* name, int flevel);
	
		string ToHex(array<uint8_t, 16> result);

		string HashFileToMD5(const string& filename);

		void SpecifyVirus(const char* md5hashstring, const char* filehash, vector<threat>& threats);

		void SearchInDB(const char* md5hashstring, vector<threat>& threats);

		void processFiles(const string& root_directory, vector<threat>& threats);

		//vector<threat> SearchForThreat(string root_directory,int counter);

};

#define VIRUS_SIGNATURE_DETECTION_API __declspec(dllexport)



extern "C" {
	VIRUS_SIGNATURE_DETECTION_API void SearchForThreat(const char* root_directory, const char* db1_root, const char* db2_root, int* threatsarray1, int* threatsarray2, int* counter);
}

#endif

