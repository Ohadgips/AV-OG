# AV BY OG ✖️🦠✖️
### [The Database 📋]([url](https://www.dropbox.com/scl/fo/oc4jdamrbko5fsenxumr3/h?rlkey=w852guzqbsl7uids5w2iae1vv&dl=0))


⚙️💻 To Run The Program Make Sure that Your **C++ Version is 17**
and make sure you downloaded sqlite3 and openssl to your computer

BEST Download With vcpkg openssl and sqlite3 or download manually like this:

[**OpenSSL Installation** ⬇️](https://www.openssl.org/source/):

download the files from the web 

Dirs: include,lib

libcrypto-3*(-x64).dll

libssl-3*(-x64).dll


Where to search for include (header (.h)) files. Go to your "Project Properties -> C/C++ -> General -> Additional Include Directories" and add OpenSSL-Win64\include (if you need to add other paths, separate them by a semicolon (;)). Now you can include in your source code OpenSSL header files.
Note that because "OpenSSL-Win64\include" dir contains an openssl subdir and under that subdir are the actual header files


Configure the linker ⚙️:

Where to search for libraries. You can do that by going to your "Project Properties -> Linker -> General -> Additional Library Directories" and adding $openssl-3.2.0\lib (again if there are multiple paths, separate them by ;)

"OpenSSL-Win64\lib" dir contains a bunch of .lib files. Out of those, you will need libcrypto-3*(-x64).lib and / or libssl-3*(-x64).lib. Go to your "Project Properties -> Linker -> Input -> Additional Dependencies" and add those 2 libraries next to the existing ones

For each of the 2 libraries, there are 2 variants:

The "normal" one

Another one ending in "_static"


[**Sqlite3  Installation** ⬇️](https://www.sqlite.org/download.html):

on the web, download amalgamation file

or on completion compile both together c++ or download sqlite3 dll from the same web page
Copy them to your project directory and open a Visual Studio command prompt (terminal in the View menu). Browse to the directory that you've copied the files to and type LIB /DEF:sqlite3.def. This will create a library file for VS to use. Add this file to your project dependencies at Project Properties -> Configuration Properties -> Linker -> Input -> Additional Dependencies


To run the program you have to open the sln and run it or g++ in the commend to test plant the tester in your dir and set the root to on of the dirs to it and thats it (make sure to allow the eicar.txt on the computer because Microsoft anti-virus will probably block it)


NOTE 🗒️: Eicar.txt is not a virus it is just a tester that is used to test anti-virus without causing any harm
