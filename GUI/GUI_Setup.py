from .AV_GUI import Ui_AV_App
from PyQt5.QtCore import pyqtSignal,Qt
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton, QWidget,QFileDialog,QVBoxLayout
from PyQt5.uic import loadUi
from PyQt5.QtGui import QMovie
import sys,os,ctypes,threading

def restore_file(widget):
    dll_path = os.path.abspath(r'./DLLs/VirusHandle.dll')
    VH_dll = ctypes.CDLL(dll_path)
    widget.fileStatus.setText(str("Allowed"))
    Allow_Func = VH_dll.restorefile
    Allow_Func.argtypes = [ctypes.c_wchar_p]
        
    path = widget.fileName.text()
    filpath_wchar = ctypes.c_wchar_p(path)
    Allow_Func(filpath_wchar)
    widget.allowFileBtn.hide()
    widget.deleteFileBtn.hide()
    
def delete_file(widget):
    dll_path = os.path.abspath(r'./DLLs/VirusHandle.dll')
    VH_dll = ctypes.CDLL(dll_path)
    widget.fileStatus.setText(str("Deleted"))
    Delete_Func = VH_dll.deletefile
    Delete_Func.argtypes = [ctypes.c_wchar_p]
        
    path = widget.fileName.text()
    filpath_wchar = ctypes.c_wchar_p(path)
    Delete_Func(filpath_wchar)
    Delete_Func(path.encode())
    widget.allowFileBtn.hide()
    widget.deleteFileBtn.hide()

def get_default_download_folder():
    # Get the user's home directory
    home_dir = os.path.expanduser("~")

    # Determine the default download directory based on the platform
   
    if os.name == 'nt':  # Windows
        return os.path.join(home_dir, 'Downloads')
    else:
        return home_dir




class Threat_UI(QWidget):
    
    def __init__(self,window,file_name,filetype):
        ui_path = os.path.abspath(r'./GUI/UI/File_Results.ui')        
        self.widget = loadUi(ui_path)
        self.widget.fileName.setText(str(file_name))
        self.widget.fileType.setText(str(filetype))
        self.widget.fileStatus.setText("Quarantined")
        window.add_to_scorll_area(self.widget)
        dll_path = os.path.abspath(r'./DLLs/VirusHandle.dll')
        VH_dll = ctypes.CDLL(dll_path)
        #if "Quarantine" not in file_name:
        Q_Func = VH_dll.quarantinefile
        
        Q_Func.argtypes = [ctypes.c_wchar_p,ctypes.c_wchar_p]
        file_name_wchar = ctypes.c_wchar_p(file_name)
        file_type_wchar = ctypes.c_wchar_p(filetype)

        Q_Func(file_name_wchar,file_type_wchar)
        self.widget.allowFileBtn.clicked.connect(lambda: restore_file(self.widget))
        self.widget.deleteFileBtn.clicked.connect(lambda: delete_file(self.widget))
    
    @classmethod
    def init_text_setup_only(cls, window, file_name, filetype):
        instance = cls.__new__(cls) 
        instance.restore_setup(window, file_name, filetype)
        return instance
    
    def restore_setup(self,window,file_name,filetype):
        ui_path = os.path.abspath(r'./GUI/UI/File_Results.ui')        
        self.widget = loadUi(ui_path)
        self.widget.fileName.setText(str(file_name))
        self.widget.fileType.setText(str(filetype))
        self.widget.fileStatus.setText("Quarantined")
        window.add_to_scorll_area(self.widget)
        self.widget.allowFileBtn.clicked.connect(lambda: restore_file(self.widget))
        self.widget.deleteFileBtn.clicked.connect(lambda: delete_file(self.widget))


class AV_Application(QMainWindow):
    start_other_function = pyqtSignal()
    def __init__(self):
        super(AV_Application,self).__init__()

        self.ui = Ui_AV_App()
        self.ui.setupUi(self) 
        self.ui.stackedWidget.setCurrentIndex(3)
        self.ui.scanBtn.setEnabled(False)
        self.ui.scanBtn.hide()
        self.scanBtn = self.ui.scanBtn
        self.filePath = self.ui.filePath
        self.loading = self.ui.loadingLabel
        script_dir = os.path.dirname(os.path.abspath(__file__))
        gif_path = os.path.join(script_dir, "Dual_Ring.gif")
        if not os.path.exists(gif_path):
            print(f"Error: The file {gif_path} does not exist.")
        self.movie = QMovie(gif_path)
        if not self.movie.isValid():
            print(f"Error: The movie {gif_path} is not valid.")
        self.loading.setMovie(self.movie)
        self.loading.hide()
        self.container_layout = QVBoxLayout(self.ui.filesResults)
        self.container_layout.setAlignment(Qt.AlignTop)
        self.container_layout.setContentsMargins(0, 0, 0, 0)
        self.container_layout.setSpacing(5)
        self.ui.exitBtn.clicked.connect(self.quit) # type: ignore

    def quit(self):
        QApplication.instance().quit()  
        sys.exit(0)   
    
    def add_to_scorll_area(self,widget):
         self.container_layout.insertWidget(0, widget)
         self.container_layout.update()
         
    def update_last_scan(self,date,threats,files):
        self.ui.scanTime.setText("Last Scan At: " + date)
        self.ui.numThreats.setText(str(threats)+" Threats Found")
        self.ui.numScanned.setText(str(files)+" Files Scanned")

    def open_file_dialog(self):
        print("open_file_dialog")
        path, ok = QFileDialog.getOpenFileName(self,"Select File ",get_default_download_folder(),"All Files (*)")
        dialog = QFileDialog()
        self.ui.filePath.setText(path)
        if self.existing_path():
            self.ui.scanBtn.setEnabled(True)
            self.ui.scanBtn.show()
        else:
            self.ui.scanBtn.setEnabled(False)
            self.ui.scanBtn.hide()

# enable the scan button if the path exists
    def existing_path(self):
        print("Checking Path")
        if os.path.exists(self.ui.filePath.text()):
            print("Existing Path")
            return True
        return False

    def open_folder_dialog(self):
        print("open_file_dialog")
        path = QFileDialog.getExistingDirectory(self,"Select A File ", get_default_download_folder(),QFileDialog.ShowDirsOnly)
        dialog = QFileDialog()
        self.ui.filePath.setText(path) 
        if self.existing_path():
            self.ui.scanBtn.setEnabled(True)
            self.ui.scanBtn.show()
        else:
            self.ui.scanBtn.setEnabled(False)
            self.ui.scanBtn.hide()

   
    def color_all_button_back(self):
        default = """QPushButton{\n\
    font: 12pt \"Alata\";\n\
    color: rgb(0, 62, 41);\n\
    padding: 2px 5px;\n\
    margin: 0;\n\
    background-color: transparent;\n\
    border-top-left-radius: 10px;\n\
    border-top-right-radius: 10px;\n\
    }\n\n\
   QPushButton:hover {\n\
   background:rgba(75, 117, 102, 90);\n\
    }"""
        self.ui.theatsBtn.setStyleSheet(default)
        self.ui.scansBtn.setStyleSheet(default)

    def turn_button_on(self,button):
        button.setStyleSheet("QPushButton{\n\
    font: 12pt \"Alata\";\n\
    color: rgb(0, 62, 41);\n\
    padding: 2px 5px;\n\
    margin: 0;\n\
    background-color: rgb(255, 255, 255);\n\
    border-top-left-radius: 10px;\n\
    border-top-right-radius: 10px;\n\
    }\n\n\
   QPushButton:hover {\n\
   background: rgb(235, 235, 235);\n\
    }")

    def on_scansBtn_clicked(self):
        self.color_all_button_back()
        self.turn_button_on(self.ui.scansBtn)
        self.ui.stackedWidget.setCurrentIndex(1)
        
    def on_theatsBtn_clicked(self):
        self.color_all_button_back()
        self.turn_button_on(self.ui.theatsBtn)
        self.ui.stackedWidget.setCurrentIndex(0)
    
    def on_infoBtn_clicked(self):
        self.color_all_button_back()
        self.ui.stackedWidget.setCurrentIndex(3)
   
    def on_helpBtn_clicked(self):
        self.color_all_button_back()
        self.ui.stackedWidget.setCurrentIndex(2)     

    def on_filePathBtn_toggled(self):
        self.open_file_dialog()   

    def on_folderPathBtn_toggled(self):
        self.open_folder_dialog()           
    
    def scan_result_update(self,time,threats,scanned):
        self.ui.scanTime.setText("Last Scan Time: " + time)
        self.ui.numScanned.setText(scanned + " Files Scanned")
        self.ui.numThreats.setText(threats + " Threats Found")
    
            
def get_and_set_all_quarantined_files(window):
        dll_path = os.path.abspath(r'./DLLs/VirusHandle.dll')
        VH_dll = ctypes.CDLL(dll_path)
        Q_Func = VH_dll.getquarantinedfiles
        Q_Func.argtypes = [
        ctypes.POINTER(ctypes.POINTER(ctypes.c_wchar_p)),
        ctypes.POINTER(ctypes.c_int)]
        files = ctypes.POINTER(ctypes.c_wchar_p)()
        count = ctypes.c_int()
        Q_Func(ctypes.byref(files), ctypes.byref(count))
        if files:
            for i in range(count.value):
                original_path = files[2 * i]
                file_type = files[2 * i + 1]
                Threat_UI.init_text_setup_only(window,original_path,file_type)
                print(f'Original Path: {original_path}, Type: {file_type}')

def start_GUI():
    app = QApplication(sys.argv)
    window = AV_Application()
    window.show()   

    return app,window







