import os
import ctypes

# Add the directory containing your DLL to the system path
current_directory = os.path.dirname(os.path.abspath(__file__))
os.environ['PATH'] += ';' + current_directory

# Load the DLL using ctypes
try:
    dll_path = os.path.join(current_directory, 'VS_Detection.dll')
    mylib = ctypes.CDLL(dll_path)
    print("DLL loaded successfully.")
except Exception as e:
    print("Error loading DLL:", e)