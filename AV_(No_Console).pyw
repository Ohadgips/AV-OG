from GUI import GUI_Setup
from WindowsMalwareDetection import PE_ML
import sys,os,threading,time,ctypes
from PyQt5.QtCore import QThread, pyqtSignal, QObject
from datetime import datetime
class Threat(ctypes.Structure):
    _fields_ = [("filepathname", ctypes.c_wchar_p), ("threattype", ctypes.c_char_p)]

def scan_time_and_date():
    today = datetime.now()
    format_date = today.strftime("%d/%m/%Y %H:%M:%S")
    return format_date

# handling threats from the VSD dll
def VSD_threats_handle(window,VSD_list, WMD_list):
   if VSD_list:
        for threat in VSD_list: 
            GUI_Setup.Threat_UI(window,threat[0],threat[1])
   if WMD_list:
        for threat in WMD_list: 
            GUI_Setup.Threat_UI(window,threat[0],threat[1])

def count_files(path):
    count = 0
    if os.path.isdir(path):
        for root_dir, cur_dir, files in os.walk(path):
            count += len(files)
            print("File Counter: ",count)
        if count == 0:return 1
        else: return count
    else: return 1


def virus_siganture_detection(path,threats_counter,threats_list):
    try:
        # make sure there is not error with the paths
        normalized_path = os.path.normpath(path)
        print(normalized_path)
        DIRNAME = os.path.dirname(os.path.abspath(__file__))
        dll_path = os.path.abspath(DIRNAME + '\\DLLs\\Virus_Signature_Detection.dll')
        dll_path = os.path.normpath(dll_path)
        VSD_dll = ctypes.CDLL(dll_path)
        VSD_Func = VSD_dll.SearchForThreat

        VSD_Func.argtypes = [ctypes.c_wchar_p,ctypes.POINTER(Threat) ,ctypes.c_char_p ,ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
        counter = ctypes.c_int(0)
        print("files num: ",threats_counter[0])
        threats_array = (Threat * threats_counter[0])()
        path_wchar = ctypes.c_wchar_p(normalized_path)

        #  dll func
        VSD_Func (path_wchar,threats_array ,DIRNAME.encode() + b'.\\Data\\VS1.db',DIRNAME.encode() + b'.\\Data\\VS2.db',ctypes.byref(counter))
        
        threats_counter[0] = counter.value
        
        for i in range(threats_counter[0]):
            threat = threats_array[i]
            if threat.filepathname:
                filepathname = threat.filepathname
                threattype = threat.threattype.decode('utf-8')
                threats_list.append((filepathname, threattype))
                print("file: ",(filepathname, threattype))

        if threats_list:
            for threat in threats_list:
                print("threat: ",threat)
        print("Threats VSD: ",threats_counter[0])
    
    except Exception as e:
        print("Error:", e)

def windows_malware_detection(exe_files,threats_counter,threats_list):
    t_counter = 0
    exe_types = {0: "Benign", 1: "RedLineStealer" ,2: "Downloader" ,3: "RemoteAccessTrojan" , 4:"BankingTrojan" , 5:"SnakeKeyLogger" ,6:"Spyware"}
    print(exe_files)
    if isinstance(exe_files, list):
        for path in exe_files:
            file_path,file_type = PE_ML.multi_models_predict_exe(os.path.normpath(path))
            if file_type != 0:
                t_counter += 1
                threats_list.append((file_path,exe_types[file_type]))
    else:
        file_path,file_type = PE_ML.multi_models_predict_exe(os.path.normpath(exe_files))
        if file_type != 0:
            t_counter += 1
            threats_list.append((file_path,exe_types[file_type]))

    threats_counter[0] = t_counter
    print("Threats VSD: ",threats_counter[0])

# do the scan in a thread so it will not crush the app    
class Scan_Worker(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)

    def __init__(self, files_path,window):
        super().__init__()
        self.files_path = files_path
        self.window = window
        self.VSD_threat_list = []  # Instance variables to store the lists
        self.WMD_threat_list = []
    
    def scan_files(self):

        date_start = scan_time_and_date(); start_time  = time.time()
    
        WMD_threats = [0] ;VSD_threats = [0] ; files_counter = 0
        files_counter = count_files(self.files_path)
        VSD_threats[0] = files_counter
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
        
            VSD_thread = threading.Thread(target=virus_siganture_detection,args= (self.files_path,VSD_threats,self.VSD_threat_list))
            VSD_thread.start()          
        
            # only if there is exe files will run the thread of the WMD
            if exe_files:
                WMD_thread = threading.Thread(target=windows_malware_detection,args=(exe_files,WMD_threats,self.WMD_threat_list))
                WMD_thread.start()
                WMD_thread.join()
            VSD_thread.join()         
    
        # For a file path        
        else:
            VSD_thread = threading.Thread(target=virus_siganture_detection,args= (self.files_path,VSD_threats,self.VSD_threat_list))
            VSD_thread.start()          
            if self.files_path.endswith(".exe"):
                print(self.files_path)
                WMD_thread = threading.Thread(target=windows_malware_detection,args=(self.files_path,WMD_threats,self.WMD_threat_list))
                WMD_thread.start()
                WMD_thread.join()
            VSD_thread.join()    

    
        end_time = time.time()
        print("data: ", self.VSD_threat_list, self.WMD_threat_list)
        threats_counter = VSD_threats[0] + WMD_threats[0]
        elapsed_time = round(end_time - start_time, 2)
        self.window.scan_result_update(date_start + " (Lasted For " + str(elapsed_time) + " s)", str(threats_counter), str(files_counter))
        thread.quit()

# setting the scan button
def start_scan(path,window):
    global thread, worker
    window.scanBtn.hide()
    window.movie.start()
    window.loading.show()
    worker = Scan_Worker(path,window)
    thread = QThread()
    worker.moveToThread(thread)

    thread.started.connect(worker.scan_files)
    worker.finished.connect(thread.quit)
    thread.finished.connect(lambda: print("Thread finished"))
    thread.finished.connect(lambda: window.scanBtn.setEnabled(True))
    thread.finished.connect(lambda: window.loading.hide())
    thread.finished.connect(lambda: window.movie.stop())
    thread.finished.connect(lambda: window.scanBtn.show())
    thread.finished.connect(lambda: window.on_theatsBtn_clicked())
    worker.progress.connect(report_progress)
    thread.finished.connect(lambda:VSD_threats_handle(window,worker.VSD_threat_list,worker.WMD_threat_list))
    worker.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)


    thread.start()
    window.scanBtn.setEnabled(False)


def report_progress(n):
    print("Task progress: {n}/5")


if __name__ == "__main__":
    DIRNAME = os.path.dirname(os.path.abspath(__file__))
    os.chdir(DIRNAME)
    app,window = GUI_Setup.start_GUI()
    GUI_Setup.get_and_set_all_quarantined_files(window)
    window.scanBtn.clicked.connect(lambda: start_scan(str(window.filePath.text()),window))

    sys.exit(app.exec_()) 
