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

struct threat {
	const char* filepathname;
	const char* threattype;
	//threat(const char* _filepathname,  const char* _threattype);
	threat() : filepathname(nullptr), threattype(nullptr) {}

	threat(const char* _filepathname, const char* _threattype) {
		size_t filepathname_len = strlen(_filepathname) + 1;
		filepathname = new char[filepathname_len];
		strcpy_s(const_cast<char*>(filepathname), filepathname_len, _filepathname);

		size_t threattype_len = strlen(_threattype) + 1;
		threattype = new char[threattype_len];
		strcpy_s(const_cast<char*>(threattype), threattype_len, _threattype);
	}
	~threat() {
		std::cout << "Destroying threat with file: " << filepathname << " and type: " << threattype << std::endl;
		delete[] filepathname;
		delete[] threattype;
	}

	// Copy constructor
	threat(const threat& other) {
		std::cout << "Copying threat with file: " << other.filepathname << " and type: " << other.threattype << std::endl;

		size_t filepathname_len = strlen(other.filepathname) + 1;
		filepathname = new char[filepathname_len];
		strcpy_s(const_cast<char*>(filepathname), filepathname_len, other.filepathname);

		size_t threattype_len = strlen(other.threattype) + 1;
		threattype = new char[threattype_len];
		strcpy_s(const_cast<char*>(threattype), threattype_len, other.threattype);
	}

	threat& operator=(const threat& other) {
		if (this == &other) return *this; 

		std::cout << "Assigning threat with file: " << other.filepathname << " and type: " << other.threattype << std::endl;

		delete[] filepathname;
		delete[] threattype;

		size_t filepathname_len = strlen(other.filepathname) + 1;
		filepathname = new char[filepathname_len];
		strcpy_s(const_cast<char*>(filepathname), filepathname_len, other.filepathname);

		size_t threattype_len = strlen(other.threattype) + 1;
		threattype = new char[threattype_len];
		strcpy_s(const_cast<char*>(threattype), threattype_len, other.threattype);

		return *this;
	}
};

class VirusSignature
{
	private:
		vector <string> VirusSign;
		sqlite3* DB1;
		sqlite3* DB2;

	public:
		VirusSignature(const char* db1_path,const char* db2_path); // constructor
			
	
		void AddToTable(sqlite3* DB, const char* str, int size, const char* name, int flevel); // adding new found virus to db (not in use for now)
	
		string ToHex(array<uint8_t, 16> result); //transferring to string md5 like in the db

		string HashFileToMD5(string filename); //transferring file to md5

		const char* SpecifyVirus(const char* md5hashstring, const char* filehash); // get file type from the database

		const char* SearchInDB(const char* md5hashstring); // search if the given file is a virus by the signatures dbs

		void processFiles(string root_directory, vector<threat>& threats); // process folder or file given


};

#define VIRUS_SIGNATURE_DETECTION_API __declspec(dllexport)


#ifdef VIRUS_SIGNATURE_DETECTION_API
extern "C" {
#endif
	
		__declspec(dllexport) void SearchForThreat(const char* root_directory, threat* threatlist, const char* db1_root, const char* db2_root, int* counter);
	
#ifdef VIRUS_SIGNATURE_DETECTION_API
}
#endif


#endif

