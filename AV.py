from GUI import GUI_Setup
from WindowsMalwareDetection import PE_ML
import sys,os,threading,shutil,time,ctypes
from PyQt5.QtCore import QThread, pyqtSignal, QObject
from datetime import datetime
import ctypes,sqlite3
import numpy as np 

def scan_time_and_date():
    today = datetime.now()
    format_date = today.strftime("%d/%m/%Y %H:%M:%S")
    return format_date

# handling threats from the VSD dll
def VSD_threats_handle(DBlist1, DBlist2):
    con = sqlite3.connect("./Data/VS1.db")
    cursor = con.cursor()
    for rowid in DBlist1: 
        cursor.execute("SELECT  FROM countries WHERE number >= 5")
        result = cursor.fetchall()

def count_files(path):
    count = 0
    if os.path.isdir(path):
        for root_dir, cur_dir, files in os.walk(path):
            count += len(files)
            print("File Counter: ",count)
        if count == 0:return 1
        else: return count
    else: return 1


def virus_siganture_detection(window,path,threats_counter,files_number):
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
    GUI_Setup.VSD_threats_handle(threats_result1,threats_result2)
    print(threats_result1)
    print(threats_result2)
    print("Threats VSD: ",threats_counter)

def windows_malware_detection(window,exe_files,threats_counter):
    t_counter = 0
    exe_types = {0: "Benign", 1: "RedLineStealer" ,2: "Downloader" ,3: "RemoteAccessTrojan" , 4:"BankingTrojan" , 5:"SnakeKeyLogger" ,6:"Spyware"}
    print(exe_files)
    if isinstance(exe_files, list):
        for path in exe_files:
            file_path,file_type = PE_ML.multi_models_predict_exe(path)
            if file_type != 0:
                t_counter += 1
                
                handle_virus = GUI_Setup.Threat_UI(window,file_path,exe_types[file_type]) # handle virus when found
    else:
        file_path,file_type = PE_ML.multi_models_predict_exe(exe_files)
        if file_type != 0:
            t_counter += 1
            handle_virus = GUI_Setup.Threat_UI(window,file_path,exe_types[file_type]) # handle virus when found
    threats_counter[0] = t_counter
    print("Threats VSD: ",threats_counter[0])

# do the scan in a thread so it will not crush the app    
class Scan_Worker(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)
    
    def __init__(self, files_path, window):
        super().__init__()
        self.files_path = files_path
        self.window = window
    
    def scan_files(self):

        date_start = scan_time_and_date()
        start_time  = time.time()
    
        WMD_threats = [0]
        VSD_threats = [0]
        files_counter = 0
        files_counter = count_files(self.files_path)
        # For a folder path
        if os.path.isdir(self.files_path):
            exe_files = []
            # list of all exe_files
            for root, dirs, files in os.walk(self.files_path):
                for file in files:
                    path = os.path.join(root, file)
                    if file.endswith(".exe"):
                        if str(path) not in exe_files:
                            print("exe file: ",str(path))
                            exe_files.append(path)
                            print(str(exe_files))
        
            VSD_thread = threading.Thread(target=virus_siganture_detection,args= (self.files_path,VSD_threats,files_counter))
            VSD_thread.start()          
        
            # only if there is exe files will run the thread of the WMD
            if exe_files:
                WMD_thread = threading.Thread(target=windows_malware_detection,args=(window,exe_files,WMD_threats))
                WMD_thread.start()
                WMD_thread.join()
            VSD_thread.join()         
    
        # For a file path        
        else:
            VSD_thread = threading.Thread(target=virus_siganture_detection,args= (self.files_path,VSD_threats,files_counter))
            VSD_thread.start()          
            if self.files_path.endswith(".exe"):
                print(self.files_path)
                WMD_thread = threading.Thread(target=windows_malware_detection,args=(window,self.files_path,WMD_threats))
                WMD_thread.start()
                WMD_thread.join()
            VSD_thread.join()    

    
        end_time = time.time()
        print("data: ", VSD_threats, WMD_threats)
        threats_counter = VSD_threats[0] + WMD_threats[0]
        elapsed_time = round(end_time - start_time, 2)
        self.window.scan_result_update(date_start + " (Lasted For " + str(elapsed_time) + " s)", str(threats_counter), str(files_counter))
        thread.quit()

# setting the scan button
def start_scan(path,window):
    global thread, worker
    window.scanBtn.hide()
    worker = Scan_Worker(path, window)
    thread = QThread()
    worker.moveToThread(thread)

    thread.started.connect(worker.scan_files)
    worker.finished.connect(thread.quit)
    worker.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    thread.finished.connect(lambda: print("Thread finished"))
    thread.finished.connect(lambda: window.scanBtn.setEnabled(True))
    thread.finished.connect(lambda: window.scanBtn.show())
    worker.progress.connect(report_progress)

    thread.start()
        

    window.scanBtn.setEnabled(False)


def report_progress(n):
    print("Task progress: {n}/5")


if __name__ == "__main__":

    app,window = GUI_Setup.start_GUI()
    #window.scanBtn.clicked.connect(lambda: scan_button(str(window.filePath.text()),window))
    window.scanBtn.clicked.connect(lambda: start_scan(str(window.filePath.text()),window))

    sys.exit(app.exec_()) 
