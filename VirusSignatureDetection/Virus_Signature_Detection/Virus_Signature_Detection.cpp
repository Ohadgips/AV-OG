#include "VirusSignature.h"
#include <vector>
#include <string>
#include <cstring>
#include <vector>
using namespace std;



extern "C" __declspec(dllexport) void SearchForThreat(string root_directory,int threatsarray1[], int threatsarray2[], int& counter) {
    VirusSignature classhandler = VirusSignature();
    vector<VirusSignature::threat> threats;
    classhandler.processFiles(root_directory, threats);
    counter = threats.size();
    cout << counter << endl;
    if (!threats.empty()) {
        int array1 = 0, array2 = 0;
        for (int i = 0; i < counter; i++)
        {
            if (threats[i].database == 1) {
                threatsarray1[array1] = threats[i].id;
                array1++;
            }
            if (threats[i].database == 2) {
                threatsarray1[array2] = threats[i].id;
                array2++;
            }
        }
    }
}




/*
int main()
{
    int counter = 0;
    int array[100] = {0};
    int array2[100] = {0};
    SearchForThreat("C:\\Users\\USER\\Downloads\\", array, array2, counter);
    cout << counter << endl;
    if (counter != 0) {
        cout << "DB1: " << endl;
        for (int i = 0; i < 100 && array[i] != 0; i++)
        {
            cout << array[i] << endl;
        }
        cout << "DB2: " << endl;
        for (int i = 0; i < 100 && array2[i] != 0; i++)
        {
            cout << array2[i] << endl;
        }
    }

}
*/
