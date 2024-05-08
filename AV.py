from GUI import GUI_Setup
from WindowsMalwareDetection import PE_ML
import sys,os,threading,shutil,time,ctypes
from datetime import date

def scan_time_and_date():
    today = date.now()
    format_date = today.strftime("%d/%m/%Y %H:%M:%S")
    return format_date

def count_files(path):
    count = 0
    for root_dir, cur_dir, files in os.walk(path):
        count += len(files)
    return count

def virus_siganture_detection(path):
    threats_counter = 0
    pass

def windows_malware_detection(exe_files):
    threats_counter = 0
    
    for path in exe_files:
        file_path,file_type = PE_ML.multi_models_predict_exe(path)
        if file_type != 0:
            threats_counter += 1
            threat_handle(file_path,file_type)
    pass

def scan_files(path):
    date_start = scan_time_and_date()
    start_time  = time.time()
    WMD_threats = None
    VSD_threats = None
    files_counter = None
    if os.path.isdir(path):
        exe_files = []
        # list of all exe_files
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".exe"):
                    exe_files.append(os.path.join(root, file))
        
        counter_thread = threading.Thread(target=count_files,args=path)
        # only if there is exe files will run the thread of the WMD
        if not exe_files:
            WMD_thread = threading.Thread(target=windows_malware_detection,args=exe_files)
        VSD_thread = threading.Thread(target=virus_siganture_detection,args=path)                
            
    else:
        pass
    
    end_time = time.time()
    theat_counter = VSD_threats + WMD_threats
    elapsed_time = round(end_time - start_time, 2)
    return date_start + " (Lasted For " + elapsed_time + " s)", theat_counter, files_counter

def threat_handle(threat_path, threat_type):
    pass

if __name__ == "__main__":

    app,window = GUI_Setup.start_GUI()
    
    sys.exit(app.exec_()) 
