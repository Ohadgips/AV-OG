import pefile,re,cpp_demangle

def decode_mangled_cpp(to_decode):
    to_decode_str = to_decode.decode('utf-8')
    print(to_decode_str)
    decoded_symbol = cpp_demangle.demangled(to_decode_str)
    print(type(decoded_symbol))
    return decoded_symbol
    
# Check for mangled C++ names
def is_mangled_cpp_name(function_name):
    function_name_str = function_name.decode('utf-8')
    return any(char in function_name_str for char in ['?', '$', '@'])

def get_imported_functions(pe_file_path):
    pe = pefile.PE(pe_file_path)
    pe.parse_data_directories()

    imported_functions = set()

    # Iterate through imported DLLs
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8")
        # Iterate through imported functions from each DLL
        for imp in entry.imports:
            name = imp.name
            if is_mangled_cpp_name(imp.name) == False:
                name = imp.name.decode("utf-8")
                imported_functions.add((dll_name,name))

    return imported_functions

if __name__ == "__main__":
    pe_file_path = "C:\\Users\\USER\\Documents\\Audacity\\audacity.exe"
    imported_functions = get_imported_functions(pe_file_path)
    for imp in imported_functions:
        print(imp[1]+",")

    