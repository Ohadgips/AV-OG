#pragma once
#ifndef VIRUSHANDLE_H
#define VIRUSHANDLE_H

#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <windows.h>
#include <Shlwapi.h>
#include <string>
#include <vector>
#include <sqlite3.h> 
#include "pathDB.h"
#pragma comment(lib, "Shlwapi.lib")
using namespace std;
namespace fs = std::filesystem;



#define VIRUS_HANDLE_API __declspec(dllexport)



extern "C" {
	VIRUS_HANDLE_API void quarantinefile(const char* filePath);
	VIRUS_HANDLE_API void deletefile(const char* filepath);
	VIRUS_HANDLE_API void restorefile(const char* filepath);

}

#endif