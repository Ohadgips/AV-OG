#include "VirusSignature.h"
#include <cstring>
using namespace std;
using namespace filesystem;


//connect to DB
sqlite3* ConnectToDB(string dbname)
{
    sqlite3* DB;
    int res;
    res = sqlite3_open(dbname.c_str(), &DB);

    if (res != SQLITE_OK) {
        cerr << "Error open DB reopen the app" << sqlite3_errmsg(DB);
        exit(-1);
    }
    else
    {
        cout << "Opened Database Successfully!" << endl;
        return DB;
    }
}

vector<string> SVList(sqlite3* DB)
{
    cout << "preparing SVList" << endl;
    vector<string> strings;
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
    vector <string> VirusSign2 = SVList(DB2);

    VirusSign.insert(VirusSign.end(), VirusSign2.begin(), VirusSign2.end());
    cout << "Finished VirusSign Creation" << endl;
}

VirusSignature::threat::threat(const std::string& _filepathname, const std::string& _threattype)
    : filepathname(_filepathname), threattype(_threattype){
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
string VirusSignature::ToHex(array<uint8_t, 16> result) {

    cout << "To Hex Start" << endl;
    std::stringstream hexStringStream;
    hexStringStream << std::hex << std::setfill('0');
    char ch;
    for (int i = 0; i < result.size(); i++) {
        ch = result[i];
        hexStringStream << setw(2) << static_cast<int>(static_cast<unsigned char>(ch)); // convert char to unsigned char (size 1 byte, non negative value, range 0-255) and to int that has a value of 1 byte use for binary data

    }
    string hexString = hexStringStream.str();
    return hexString;

}
//calculate md5 hash for file using open ssl
string VirusSignature::HashFileToMD5(const string& filename) {
    cout << "To MD5 START" << endl;
    ifstream file(filename, ios::binary);
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
        array<uint8_t, 16> result;
        EVP_DigestFinal_ex(md5Context, result.data(), nullptr);
        file.close();
        EVP_MD_CTX_free(md5Context);
        return ToHex(result);
    }
}

const char* VirusSignature::SpecifyVirus(const char* md5hashstring, const char* filehash)
{
    cout << "Specify Virus" << endl;
    sqlite3_stmt* statement;
    const char* threat_type = nullptr;
    const char* sql = "SELECT name FROM main WHERE string = ?;";
    int result = sqlite3_prepare_v2(DB1, sql, -1, &statement, nullptr);

    if (result == SQLITE_OK)
    {
        cout << "Found Virus DB1" << endl;
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
            cout << "Found Virus DB2" << endl;
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
const char* VirusSignature::SearchInDB(const char* md5hashstring)
{
    cout << "Search In DBs" << endl; const char* virus_type = nullptr;
    string filehash = HashFileToMD5(md5hashstring);
    for (const auto& element : VirusSign) {
        if (element == filehash) {
            virus_type = SpecifyVirus(md5hashstring, filehash.c_str());
            cout << "Found Virus" << endl;
        }
    }
    return virus_type;
}
// use thread to check it and make it kind of recursive
void VirusSignature::processFiles(const string& path_root, vector<threat>& threats) {
    const char* virus_type;
    if (is_directory(path_root)) {
        cout << "Process files FOLDER" << endl;
        try {
            for (const auto& entry : directory_iterator(path_root)) {
                if (!is_directory(entry.path())) {
                    string filepath = entry.path().string();
                    try {
                        file_status fstatus = status(entry);
                        if ((fstatus.permissions() & perms::owner_read) != perms::none)
                        {
                            virus_type = SearchInDB(filepath.c_str());
                            if (virus_type != nullptr)
                            {
                                threat file(filepath.c_str(), virus_type);
                                // Process or save the retrieved string here
                                threats.push_back(file);
                            }
                        }
                    }
                    catch (const filesystem_error& e) {
                        cout << "Exception " << e.what() << endl;
                        continue;
                    }
                }
                else if (is_directory(entry.path()))
                {
                    file_status fstatus = status(entry);
                    if ((fstatus.permissions() & perms::owner_read) != perms::none) {
                        try {
                            processFiles(entry.path().string(), threats);
                        }
                        catch (std::exception& e) {
                            continue;
                        }
                    }
                }
            }
        }
        catch (const exception& e)
        {
            cout << "Exception " << e.what() << endl;
        }
    }
    else if (is_regular_file(path_root)) {
        cout << "Process files FILE" << endl;
        try 
        {
            file_status fstatus = status(path_root);
            
            if (is_regular_file(fstatus) && (fstatus.permissions() & perms::owner_read) != perms::none) {
                virus_type = SearchInDB(path_root.c_str());
                if (virus_type != nullptr)
                {
                    threat file(path_root.c_str(), virus_type);
                    // Process or save the retrieved string here
                    threats.push_back(file);
                }
            }
        }
        catch (const filesystem_error& e) {
            cout << "Exception " << e.what() << endl;
        }
    }
   
}


extern "C" {
    __declspec(dllexport) Threat* SearchForThreat(const char* root_directory, const char* db1_root, const char* db2_root, int* counter)
    {
        VirusSignature classhandler = VirusSignature(db1_root, db2_root);
        cout << "CLASS HANDLER" << endl;
        vector<VirusSignature::threat> threats;
        classhandler.processFiles(root_directory, threats);
        cout << "PROCESS FILES FINISHED" << endl;
        *counter = threats.size();
        Threat* cThreatList = new Threat[*counter];
        if (!threats.empty()) {
            for (int i = 0; i < *counter; i++) {
                cThreatList[i].fileName = threats[i].filepathname.c_str();
                cThreatList[i].fileType = threats[i].threattype.c_str();
                cout << "path: " << cThreatList[i].fileName << endl;
                cout << "type: " << cThreatList[i].fileType << endl;

            }
        }
        cout << *counter << endl;
        return cThreatList;
    }

    __declspec(dllexport) void freeList(Threat* list, int count) {
        delete[] list;
    }
}
/*
int main() {

    int Counter = 0;
    Threat* t = SearchForThreat("C:/Users/USER/Downloads/Test", "VS1.DB", "VS2.DB", &Counter);
}*/
