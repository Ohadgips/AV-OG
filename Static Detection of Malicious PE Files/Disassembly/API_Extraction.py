import pefile,re
def demangle_cpp_name(mangled_name):
    # Example of regex to demangle MSVC++ decorated names
    regex = r"\?(?P<func_name>[^\@@]+)@"
    match = re.match(regex, mangled_name)
    if match:
        return match.group("func_name")
    return mangled_name

def get_imported_functions(pe_file_path):
    pe = pefile.PE(pe_file_path)

    imported_functions = set()

    # Iterate through imported DLLs
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8")
        
        # Iterate through imported functions from each DLL
        for imp in entry.imports:
            imported_functions.add((dll_name, imp.name.decode("utf-8") if imp.name else "Ordinal_" + str(imp.ordinal)))

    return imported_functions

if __name__ == "__main__":
    pe_file_path = "C:\\Users\\USER\\Documents\\Audacity\\audacity.exe"
    imported_functions = get_imported_functions(pe_file_path)
    print("Imported API Functions:")
    for api_function in imported_functions:
        print(api_function[1])
        if str(api_function[1]).startswith("??"):  # Check if it's a C++ mangled name
            api_function = list(api_function)
            api_function[1] = demangle_cpp_name(api_function[1])
        print(api_function)
    #for dll, function in imported_functions:
     #   print(f"{dll}: {function}")