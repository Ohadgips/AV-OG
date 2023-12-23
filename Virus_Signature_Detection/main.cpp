#include <algorithm>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sqlite3.h>
#include <array>
#include <filesystem>
#include <vector>
#include <algorithm>
#include "VirusSignature.h"
using namespace std;

int main()
{
    
    time_t start, end;
    time(&start);
    /*
    vector<threat> threats;
    DB = ConnectToDB();
    VirusSign = SVList(DB);

    //change the root depend on where you want to search for signatures (using big directories will take more time)
    string root_directory = "C:\\Users\\USER\\Downloads\\";*/

    VirusSignature VirusSign = VirusSignature();
    vector<VirusSignature::threat> threats = VirusSign.SearchForThreat("C:\\Users\\USER\\Downloads\\TEST\\");
        // print all threats in soon it will also make actions 
        for (const auto&  threat : threats) {
            cout << "file path: " << threat.filepathname << "\n threat type: " << threat.threattype << endl;
        }
    time(&end);
    double time_taken = double(end - start);
    cout << "Time taken by program is : " << fixed
        << time_taken << setprecision(5);
    cout << " sec " << endl;
}