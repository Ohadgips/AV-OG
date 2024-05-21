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

#ifdef VIRUS_HANDLE_API
extern "C" {
#endif
	__declspec(dllexport) void quarantinefile(const char* filePath);
	__declspec(dllexport) void deletefile(const char* filepath);
	__declspec(dllexport) void restorefile(const char* filepath);
#ifdef VIRUS_HANDLE_API
}
#endif
#endif