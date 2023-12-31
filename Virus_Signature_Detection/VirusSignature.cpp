#include "VirusSignature.h"
using namespace std;
using namespace filesystem;

//connect to DB
sqlite3* ConnectToDB()
{
    sqlite3* DB;
    int res;
    res = sqlite3_open("VS.db", &DB);

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
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(DB) << std::endl;
    }
    return strings;
}

VirusSignature::VirusSignature()
{
    DB = ConnectToDB();
    VirusSign = SVList(DB);

}

//add new signature to db (will be in more use with the behavior detection later)
void VirusSignature::AddToTable(sqlite3* DB, const char* str, int size, const char* name, int flevel)
{
    //char* messaggeError;
    int res = 0;
    const char* sql = "INSERT INTO main (string,size (bytes),name,fuctionlty level) VALUES(?,?,?,?);";
    sqlite3_stmt* statement;

    res = sqlite3_prepare_v2(DB, sql, -4, &statement, 0);
    if (res != SQLITE_OK) {
        //error
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(DB) << std::endl;
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
    const char* sql = "SELECT name FROM main WHERE string = ?;";
    int result = sqlite3_prepare_v2(DB, sql, -1, &statement, nullptr);

    if (result == SQLITE_OK)
    {
        sqlite3_bind_text(statement, 1, filehash, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(statement, 0);
            if (text) {
                threat file = { md5hashstring, reinterpret_cast<const char*>(text) };
                // Process or save the retrieved string here
                threats.push_back(file);
                //std::cout << "Value: " << text << std::endl;
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

vector<VirusSignature::threat> VirusSignature::SearchForThreat(string root_directory)
{
    vector<VirusSignature::threat> threats;
    processFiles(root_directory, threats);
    return threats;
}

    
    
