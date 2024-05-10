from GUI import GUI_Setup
from WindowsMalwareDetection import PE_ML
import sys,os,threading,shutil,time,ctypes
from datetime import date

def scan_time_and_date():
    today = date.now()
    format_date = today.strftime("%d/%m/%Y %H:%M:%S")
    return format_date

def count_files(path,count):
    for root_dir, cur_dir, files in os.walk(path):
        count += len(files)
    return count

def virus_siganture_detection(path,threats_counter):
    pass


def windows_malware_detection(exe_files,threats_counter):
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
    WMD_threats = 0 ; VSD_threats = 0; files_counter = 0
    
    # For a folder path
    if os.path.isdir(path):
        exe_files = []
        # list of all exe_files
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".exe"):
                    exe_files.append(os.path.join(root, file))
        
        counter_thread = threading.Thread(target=count_files,args=(path,files_counter))
        VSD_thread = threading.Thread(target=virus_siganture_detection,args= (path,VSD_threats))
        counter_thread.start()
        VSD_thread.start()          
        
        # only if there is exe files will run the thread of the WMD
        if not exe_files:
            WMD_thread = threading.Thread(target=windows_malware_detection,args=(exe_files,WMD_threats))
            WMD_thread.start()
            WMD_thread.join()
        
        counter_thread.join()
        VSD_thread.join()         
    
    # For a file path        
    else:
        VSD_thread = threading.Thread(target=virus_siganture_detection,args= (path,VSD_threats))
        VSD_thread.start()          
        if path.endswith(".exe"):
            WMD_thread = threading.Thread(target=windows_malware_detection,args=(exe_files,WMD_threats))
            WMD_thread.start()
            WMD_thread.join()
        VSD_thread.join()    

    
    end_time = time.time()
    threats_counter = VSD_threats + WMD_threats
    elapsed_time = round(end_time - start_time, 2)
    return date_start + " (Lasted For " + elapsed_time + " s)", threats_counter, files_counter

def threat_handle(threat_path, threat_type):
    pass

if __name__ == "__main__":

    app,window = GUI_Setup.start_GUI()
    
    sys.exit(app.exec_()) 
