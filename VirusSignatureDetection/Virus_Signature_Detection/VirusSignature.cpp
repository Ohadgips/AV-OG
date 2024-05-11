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
        std::cout << "listing" << std::endl;
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(DB) << std::endl;
    }
    return strings;
}


VirusSignature::VirusSignature()
{
    DB1 = ConnectToDB("Databases\\VS1.db");
    DB2 = ConnectToDB("Databases\\VS2.db");
    VirusSign = SVList(DB1);
    vector <string> VirusSign2 = SVList(DB2);

    VirusSign.insert(VirusSign.end(), VirusSign2.begin(), VirusSign2.end());
}

VirusSignature::threat::threat(const std::string& _filepathname, const std::string& _threattype, int _id, int _database)
    : filepathname(_filepathname), threattype(_threattype), id(_id), database(_database){
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
    if (res != SQLITE_OK) {
        std::cerr << "Error Insert" << std::endl;
        //sqlite3_free(messaggeError);
    }
    else
        std::cout << "Records created Successfully!" << std::endl;

    sqlite3_finalize(statement);
}





//transfer the data to hex
string VirusSignature::ToHex(array<uint8_t, 16> result) {


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

void VirusSignature::SpecificVirus(const char* md5hashstring, const char* filehash, vector<threat>& threats)
{
    sqlite3_stmt* statement;
    const char* sql = "SELECT rowid,name FROM main WHERE string = ?;";
    int result = sqlite3_prepare_v2(DB1, sql, -1, &statement, nullptr);

    if (result == SQLITE_OK)
    {
        sqlite3_bind_text(statement, 1, filehash, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(statement, 0);
            int rowid = sqlite3_column_int(statement, 0);
            if (text) {
                threat file ( md5hashstring, reinterpret_cast<const char*>(text),rowid,1 );
                // Process or save the retrieved string here
                threats.push_back(file);
                //std::cout << "Value: " << text << std::endl;
            }
        }
    }
    else {
        int result = sqlite3_prepare_v2(DB2, sql, -1, &statement, nullptr);
        if (result == SQLITE_OK)
        {
            sqlite3_bind_text(statement, 1, filehash, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(statement) == SQLITE_ROW) {
                const unsigned char* text = sqlite3_column_text(statement, 0);
                int rowid = sqlite3_column_int(statement, 0);
                if (text) {
                    threat file(md5hashstring, reinterpret_cast<const char*>(text), rowid,2);
                    // Process or save the retrieved string here
                    threats.push_back(file);
                    //std::cout << "Value: " << text << std::endl;
                }
            }
        }
    }
}

//Search If Signature in DB
void VirusSignature::SearchInDB(const char* md5hashstring, vector<threat>& threats)
{
    string filehash = HashFileToMD5(md5hashstring);
    for (const auto& element : VirusSign) {
        if (element == filehash) {
            SpecificVirus(md5hashstring, filehash.c_str(), threats);
            cout << "Found Virus" << endl;
        }
    }
}
// use thread to check it and make it kind of recursive
void VirusSignature::processFiles(const string& root_directory, vector<threat>& threats) {
    for (const auto& entry : directory_iterator(root_directory)) {
        if (!is_directory(entry.path())) {
            string filepath = entry.path().string();
            try {
                file_status fstatus = status(entry);
                if ((fstatus.permissions() & perms::owner_read) != perms::none)
                {
                  SearchInDB(filepath.c_str(), threats);

                }
            }
            catch (const filesystem_error& e) {
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


    
/*
extern "C++" __declspec(dllexport) vector<VirusSignature::threat> SearchForThreat(string root_directory, int counter) {
    VirusSignature classhandler = VirusSignature();
    vector<VirusSignature::threat> threats;
    classhandler.processFiles(root_directory, threats, counter);
    return threats;
}

int main()
{
    int counter = 0;
    vector<VirusSignature::threat> data = SearchForThreat("C:\\Users\\USER\\Downloads\\", counter);
    cout << counter << endl;
    for (const auto& d : data) {
        cout << d.filepathname << endl;
    }
    std::cout << std::endl;

}
*/