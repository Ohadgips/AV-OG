#ifndef VIRUSSIGNATURE_H
#define VIRUSSIGNATURE_H

#ifdef byte
#undef byte
#endif
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
#include <locale>
#include <codecvt>
#include <fcntl.h> 
//using namespace std;
namespace fs = std::filesystem;

struct threat {
	const wchar_t* filepathname;
	const char* threattype;
	//threat(const char* _filepathname,  const char* _threattype);
	threat() : filepathname(nullptr), threattype(nullptr) {}

	threat(const wchar_t* _filepathname, const char* _threattype) {
		size_t filepathname_len = wcslen(_filepathname) + 1;
		filepathname = new wchar_t[filepathname_len];
		wcscpy_s(const_cast<wchar_t*>(filepathname), filepathname_len, _filepathname);


		size_t threattype_len = strlen(_threattype) + 1;
		threattype = new char[threattype_len];
		strcpy_s(const_cast<char*>(threattype), threattype_len, _threattype);
	}
	~threat() {
		//std::wcout << L"Destroying threat with file: " << filepathname << L" and type: " << threattype << std::endl;
		delete[] filepathname;
		delete[] threattype;
	}

	// Copy constructor
	threat(const threat& other) {
		std::wcout << L"Copying threat with file: " << other.filepathname << L" and type: " << other.threattype << std::endl;

		size_t filepathname_len = wcslen(other.filepathname) + 1;
		filepathname = new wchar_t[filepathname_len];
		wcscpy_s(const_cast<wchar_t*>(filepathname), filepathname_len, other.filepathname);

		size_t threattype_len = strlen(other.threattype) + 1;
		threattype = new char[threattype_len];
		strcpy_s(const_cast<char*>(threattype), threattype_len, other.threattype);
	}

	threat& operator=(const threat& other) {
		if (this == &other) return *this; 

		std::wcout << L"Assigning threat with file: " << other.filepathname << L" and type: " << other.threattype << std::endl;

		delete[] filepathname;
		delete[] threattype;

		size_t filepathname_len = wcslen(other.filepathname) + 1;
		filepathname = new wchar_t[filepathname_len];
		wcscpy_s(const_cast<wchar_t*>(filepathname), filepathname_len, other.filepathname);

		size_t threattype_len = strlen(other.threattype) + 1;
		threattype = new char[threattype_len];
		strcpy_s(const_cast<char*>(threattype), threattype_len, other.threattype);

		return *this;
	}
};


class VirusSignature
{
	private:
		std::vector <std::string> VirusSign;
		std::vector <std::string> VirusSign2;
		sqlite3* DB1;
		sqlite3* DB2;

	public:
		VirusSignature(const char* db1_path,const char* db2_path); // constructor
			
	
		void AddToTable(sqlite3* DB, const char* str, int size, const char* name, int flevel); // adding new found virus to db (not in use for now)
	
		std::string ToHex(std::array<uint8_t, 16> result); //transferring to string md5 like in the db

		std::string HashFileToMD5(std::wstring filename); //transferring file to md5

		const char* SpecifyVirus(const wchar_t* md5hashstring, const char* filehash); // get file type from the database

		const char* SearchInDB(const wchar_t* md5hashstring); // search if the given file is a virus by the signatures dbs

		void processFiles(std::wstring root_directory, std::vector<threat>& threats); // process folder or file given


};

#define VIRUS_SIGNATURE_DETECTION_API __declspec(dllexport)


#ifdef VIRUS_SIGNATURE_DETECTION_API
extern "C" {
#endif
	__declspec(dllexport) const char* ConvertToUTF8(const wchar_t* input);
	__declspec(dllexport) void SearchForThreat(const wchar_t* root_directory, threat* threatlist, const char* db1_root, const char* db2_root, int* counter);
	
#ifdef VIRUS_SIGNATURE_DETECTION_API
}
#endif


#endif

