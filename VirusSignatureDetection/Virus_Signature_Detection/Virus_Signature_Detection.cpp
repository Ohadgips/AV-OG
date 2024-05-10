#include "VirusSignature.h"
#include <vector>
#include <string>
#include <cstring>
using namespace std;



extern "C" __declspec(dllexport) int SearchForThreat(string root_directory,int threatsarray ,int counter){
    VirusSignature classhandler = VirusSignature();
    vector<VirusSignature::threat> threats;
    classhandler.processFiles(root_directory, threats, counter);
    
    return threatsarray;
}





int main()
{
    int counter = 0;
    int array[100];
    vector<VirusSignature::threat> data = SearchForThreat("C:\\Users\\USER\\Downloads\\",array,counter);
    cout << counter << endl;
    for (const auto& d : data) {
        cout << d.filepathname << endl;
    }
    std::cout << std::endl;

}