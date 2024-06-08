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
#include <locale>
#include <codecvt>
namespace fs = std::filesystem;
#pragma comment(lib, "Shlwapi.lib")



#define VIRUS_HANDLE_API __declspec(dllexport)

#ifdef VIRUS_HANDLE_API
extern "C" {
#endif
	__declspec(dllexport) void quarantinefile(const wchar_t* filePath);
	__declspec(dllexport) void deletefile(const wchar_t* filepath);
	__declspec(dllexport) void restorefile(const wchar_t* filepath);
#ifdef VIRUS_HANDLE_API
}
#endif
#endif