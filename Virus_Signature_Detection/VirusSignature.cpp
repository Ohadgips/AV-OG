#ifdef byte
#undef byte
#endif

#include "VirusSignature.h"
#include <cstring>
#include <windows.h>
#include <locale>
#include <codecvt>


//connect to DB
sqlite3* ConnectToDB(std::string dbname)
{
    sqlite3* DB;
    int res;
    res = sqlite3_open(dbname.c_str(), &DB);

    if (res != SQLITE_OK) {
        std::cerr << "Error open DB reopen the app" << sqlite3_errmsg(DB);
        exit(-1);
    }
    else
    {
        std::cout << "Opened Database Successfully!" << std::endl;
        return DB;
    }
}

std::vector<std::string> SVList(sqlite3* DB)
{
    std::cout << "preparing SVList" << std::endl;
    std::vector<std::string> strings;
    sqlite3_stmt* statement;
    const char* sql = "SELECT string FROM main;";
    int result = sqlite3_prepare_v2(DB, sql, -1, &statement, nullptr);

    if (result == SQLITE_OK)
    {
        while (sqlite3_step(statement) == SQLITE_ROW)
        {
            const unsigned char* text = sqlite3_column_text(statement, 0);
            if (text) {
                const char* cctext = reinterpret_cast<const char*>((text));
                strings.push_back(cctext);
                // Process or save the retrieved string here
            }
        }
    }
    if (result != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(DB) << std::endl;
    }
    return strings;
}

VirusSignature::VirusSignature(const char* db1_path,const char* db2_path)
{
    DB1 = ConnectToDB(db1_path);
    DB2 = ConnectToDB(db2_path);
    VirusSign = SVList(DB1);
    VirusSign2 = SVList(DB2);

    VirusSign.insert(VirusSign.end(), VirusSign2.begin(), VirusSign2.end());
    std::cout << "Finished VirusSign Creation" << std::endl;
}


//add new signature to db (will be in more use with the behavior detection later)
void VirusSignature::AddToTable(sqlite3* DB2, const char* str, int size, const char* name, int flevel)
{
    //char* messaggeError;
    int res = 0;
    const char* sql = "INSERT INTO main (string,size (bytes),name,fuctionlty level) VALUES(?,?,?,?);";
    sqlite3_stmt* statement;

    res = sqlite3_prepare_v2(DB2, sql, -4, &statement, 0);
    if (res != SQLITE_OK) {
        //error
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(DB2) << std::endl;
    }

    sqlite3_bind_text(statement, 1, str, -1, SQLITE_STATIC); sqlite3_bind_int(statement, 2, size); sqlite3_bind_text(statement, 3, name, -1, SQLITE_STATIC); sqlite3_bind_int(statement, 4, flevel);

    res = sqlite3_step(statement);

    //error
    if (res != SQLITE_DONE) {
        std::cerr << "Error Insert" << std::endl;
        //sqlite3_free(messaggeError);
    }
    else
        std::cout << "Records created Successfully!" << std::endl;

    sqlite3_finalize(statement);
}





//transfer the data to hex
std::string VirusSignature::ToHex(std::array<uint8_t, 16> result) {

    //cout << "To Hex Start" << endl;
    std::stringstream hexStringStream;
    hexStringStream << std::hex << std::setfill('0');
    char ch;
    for (int i = 0; i < result.size(); i++) {
        ch = result[i];
        hexStringStream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(ch)); // convert char to unsigned char (size 1 byte, non negative value, range 0-255) and to int that has a value of 1 byte use for binary data

    }
    std::string hexString = hexStringStream.str();
    return hexString;

}
//calculate md5 hash for file using open ssl
std::string VirusSignature::HashFileToMD5(std::wstring filename) {
    //cout << "To MD5 START" << endl;
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return "0";
    }
    else {
        EVP_MD_CTX* md5Context = EVP_MD_CTX_new();
        EVP_MD_CTX_init(md5Context);
        EVP_DigestInit_ex(md5Context, EVP_md5(), nullptr);
        const size_t bufferSize = 4096;
        char buffer[bufferSize];
        while (!file.eof()) {
            file.read(buffer, bufferSize);
            EVP_DigestUpdate(md5Context, buffer, file.gcount());
        }
        std::array<uint8_t, 16> result;
        EVP_DigestFinal_ex(md5Context, result.data(), nullptr);
        file.close();
        EVP_MD_CTX_free(md5Context);
        return ToHex(result);
    }
}

const char* VirusSignature::SpecifyVirus(const wchar_t* md5hashstring, const char* filehash)
{
    //cout << "Specify Virus" << endl;
    sqlite3_stmt* statement;
    const char* threat_type = nullptr;
    const char* sql = "SELECT name FROM main WHERE string = ?;";
    int result = sqlite3_prepare_v2(DB1, sql, -1, &statement, nullptr);

    if (result == SQLITE_OK)
    {
        std::cout << "Found Virus DB1" << std::endl;
        sqlite3_bind_text(statement, 1, filehash, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(statement, 0);
            if (text) {
                threat_type = reinterpret_cast<const char*>(text);
                // Process or save the retrieved string here
                //std::cout << "Value: " << text << std::endl;
            }
        }
    }
    else {
        int result = sqlite3_prepare_v2(DB2, sql, -1, &statement, nullptr);
        if (result == SQLITE_OK)
        {
            std::cout << "Found Virus DB2" << std::endl;
            sqlite3_bind_text(statement, 1, filehash, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(statement) == SQLITE_ROW) {
                const unsigned char* text = sqlite3_column_text(statement, 0);
                if (text) {
                    threat_type = reinterpret_cast<const char*>(text);
                    return reinterpret_cast<const char*>(text);
                    // Process or save the retrieved string here
                    //std::cout << "Value: " << text << std::endl;
                }
            }
        }
    }
    return threat_type;
}

//Search If Signature in DB
const char* VirusSignature::SearchInDB(const wchar_t* md5hashstring)
{
    //cout << "Search In DBs" << endl; 
    const char* virus_type = nullptr;
    std::string filehash = HashFileToMD5(md5hashstring);
    for (const auto& element : VirusSign) {
        if (element == filehash) {
            virus_type = SpecifyVirus(md5hashstring, filehash.c_str());
            std::cout << "Found Virus" << std::endl;
        }
    }
    for (const auto& element : VirusSign2) {
        if (element == filehash) {
            virus_type = SpecifyVirus(md5hashstring, filehash.c_str());
            std::cout << "Found Virus" << std::endl;
        }
    }
    return virus_type;
}



// recursive func that make sure every file is checked individually
void VirusSignature::processFiles(std::wstring path_root, std::vector<threat>& threats) {
    const char* virus_type = nullptr;
    if (fs::is_directory(path_root)) {
        std::cout << "Process files FOLDER" << std::endl;
        try {
            for (const auto& entry : fs::directory_iterator(path_root)) {
                if (!is_directory(entry.path())) {
                    std::wstring filepath = entry.path().wstring();
                    std::wcout << L"file:  " << filepath << std::endl;
                    _putws(filepath.c_str());
                    try {
                        fs::file_status fstatus = fs::status(entry);
                        if ((fstatus.permissions() & fs::perms::owner_read) != fs::perms::none)
                        {
                            virus_type = SearchInDB(filepath.c_str());
                            if (virus_type != nullptr)
                            {

                                threat file(filepath.c_str(), virus_type);
                                std::wcout << L"file:  " << file.filepathname << std::endl;
                                std::cout << " type:  " << file.threattype << std::endl;
                                if(fs::exists(file.filepathname))
                                {
                                    std::cout << "good path" << std::endl;
                                }
                                // Process or save the retrieved string here
                                threats.push_back(file);
                            }
                        }
                    }
                    catch (const fs::filesystem_error& e) {
                        std::cout << "Exception " << e.what() << std::endl;
                        continue;
                    }
                }
                else if (is_directory(entry.path()))
                {
                    fs::file_status fstatus = fs::status(entry);
                    if ((fstatus.permissions() & fs::perms::owner_read) != fs::perms::none) {
                        try {
                            processFiles(entry.path().wstring(), threats);
                        }
                        catch (std::exception& e) {
                            continue;
                        }
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cout << "Exception " << e.what() << std::endl;
        }
    }
    else if (fs::is_regular_file(path_root)) {
        std::cout << "Process files FILE" << std::endl;
        try 
        {
            fs::file_status fstatus = fs::status(path_root);
            
            if (is_regular_file(fstatus) && (fstatus.permissions() & fs::perms::owner_read) != fs::perms::none) {
                virus_type = SearchInDB(path_root.c_str());
                if (virus_type != nullptr)
                {
                    threat file(path_root.c_str(), virus_type);
                    std::wcout << L"file:  " << file.filepathname << std::endl;
                    std::cout << " type:  " << file.threattype << std::endl;
                    // Process or save the retrieved string here
                    threats.push_back(file);
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            std::cout << "Exception " << e.what() << std::endl;
        }
    }
   
}


extern "C" {
    __declspec(dllexport) void SearchForThreat(const wchar_t* root_directory, threat* threatlist, const char* db1_root, const char* db2_root, int* counter)
    {
        SetConsoleOutputCP(CP_UTF8);
        std::locale::global(std::locale("en_US.UTF-8"));

        VirusSignature classhandler = VirusSignature(db1_root, db2_root);
        std::cout << "CLASS HANDLER" << std::endl;
        std::vector<threat> threats;

        classhandler.processFiles(root_directory, threats);
        std::cout << "PROCESS FILES FINISHED" << std::endl;
        *counter = static_cast<int>(threats.size());
        std::cout << *counter << std::endl;
        for (int i = 0; i < *counter; ++i) {
            std::wcout << threats[i].filepathname << L" // ";
            std::cout << threats[i].threattype << std::endl;
            new(&threatlist[i]) threat(threats[i].filepathname, threats[i].threattype);
        }
    }
}

/* For DLL Testing
int main() {
    int Counter = 0;
    threat* t = new threat[1000];

    SearchForThreat(L"C:/Users/USER/Downloads/מבחן", t,"VS1.DB", "VS2.DB", &Counter);
    for (int i = 0; i < Counter; ++i) {
        std::wcout << t[i].filepathname << " // " << t[i].threattype << std::endl;
    }
}*/
