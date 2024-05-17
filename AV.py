from GUI import GUI_Setup
from WindowsMalwareDetection import PE_ML
import sys,os,threading,shutil,time,ctypes
from datetime import datetime
import ctypes
import numpy as np 

def scan_time_and_date():
    today = datetime.now()
    format_date = today.strftime("%d/%m/%Y %H:%M:%S")
    return format_date

def count_files(path):
    count = 0
    if os.path.isdir(path):
        for root_dir, cur_dir, files in os.walk(path):
            count += len(files)
            print("File Counter: ",count)
        if count == 0:return 1
        else: return count
    else: return 1


def virus_siganture_detection(path,threats_counter,files_number):
    #os.add_dll_directory('/VirusSignatureDetection/Virus_Signature_Detection')
    dll_path = os.path.abspath(r'./Virus_Signature_Detection.dll')
    VSD_dll = ctypes.CDLL(dll_path)
    VSD_Func = VSD_dll.SearchForThreat
    VSD_Func.argtypes = [ctypes.c_char_p,ctypes.c_char_p ,ctypes.c_char_p,ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
    VSD_Func.restype = None
    
    DBarray1 = (ctypes.c_int * files_number)()
    DBarray2 = (ctypes.c_int * files_number)()
    counter = ctypes.c_int(0)


    VSD_Func(path.encode(),b'./Data/VS1.db',b'./Data/VS2.db',DBarray1,DBarray2 ,ctypes.byref(counter))
    threats_result1 = list(DBarray1)
    threats_result2 = list(DBarray2)
    threats_counter[0] = counter.value
    print(threats_result1)
    print(threats_result2)
    print("Threats VSD: ",threats_counter)

def windows_malware_detection(exe_files,threats_counter):
    threats_counter = 0
    if isinstance(exe_files, list):
        for path in exe_files:
            file_path,file_type = PE_ML.multi_models_predict_exe(path)
            if file_type != 0:
                threats_counter[0] += 1
                threat_handle(file_path,file_type)
    else:
        file_path,file_type = PE_ML.multi_models_predict_exe(exe_files)
        if file_type != 0:
            threats_counter[0] += 1
            threat_handle(file_path,file_type)
    print("Threats VSD: ",threats_counter)
    

def scan_files(files_path,window):

    date_start = scan_time_and_date()
    start_time  = time.time()
    
    WMD_threats = [0]
    VSD_threats = [0]
    files_counter = 0
    files_counter = count_files(files_path)
    # For a folder path
    if os.path.isdir(files_path):
        exe_files = []
        # list of all exe_files
        for root, dirs, files in os.walk(files_path):
            for file in files:
                if file.endswith(".exe"):
                    exe_files.append(os.path.join(root, file))
        
        VSD_thread = threading.Thread(target=virus_siganture_detection,args= (files_path,VSD_threats,files_counter))
        VSD_thread.start()          
        
        # only if there is exe files will run the thread of the WMD
        if exe_files:
            WMD_thread = threading.Thread(target=windows_malware_detection,args=(exe_files,WMD_threats))
            WMD_thread.start()
            WMD_thread.join()
        VSD_thread.join()         
    
    # For a file path        
    else:
        VSD_thread = threading.Thread(target=virus_siganture_detection,args= (files_path,VSD_threats,files_counter))
        VSD_thread.start()          
        if files_path.endswith(".exe"):
            print(files_path)
            WMD_thread = threading.Thread(target=windows_malware_detection,args=(files_path,WMD_threats))
            WMD_thread.start()
            WMD_thread.join()
        VSD_thread.join()    

    
    end_time = time.time()
    print("data: ", VSD_threats, WMD_threats)
    threats_counter = VSD_threats[0] + WMD_threats[0]
    elapsed_time = round(end_time - start_time, 2)
    window.scan_result_update(date_start + " (Lasted For " + str(elapsed_time) + " s)", str(threats_counter), str(files_counter))

def threat_handle(threat_path, threat_type):
    print("handling")
    pass

def scan_button(path,window):
    window.scanBtn.hide() #instead of loading sequence for now
    scan_thread = threading.Thread(target=scan_files,args=(path,window))
    scan_thread.start()
    scan_thread.join()
    window.scanBtn.show()



if __name__ == "__main__":

    app,window = GUI_Setup.start_GUI()
    window.scanBtn.clicked.connect(lambda: scan_button(str(window.filePath.text()),window))
    
    sys.exit(app.exec_()) 
