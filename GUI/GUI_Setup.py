from .AV_GUI import Ui_AV_App
from PyQt5.QtCore import pyqtSignal,Qt
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton, QWidget,QFileDialog,QVBoxLayout
from PyQt5 import uic
import sys,os,ctypes,threading
#from . import AV_Icons_rc


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
        self.widget = uic.load('./UI/File_Results.ui"')
        self.widget.fileName.setText(str(file_name))
        self.widget.fileType.setText(str(filetype))
        self.widget.fileStatus.setText("Quarantined")
        dll_path = os.path.abspath(r'./VirusHandle.dll')
        self.VH_dll = ctypes.CDLL(dll_path)
        Q_Func.restype = None
        
        Q_Func = self.VH_dll.quarantinefile
        Q_Func.argtypes = [ctypes.c_char_p];
        Q_Func(file_name.encode())
        window.add_to_scorll_area(self.widget)

    def on_allowFileBtn_toggled(self):
        self.widget.fileStatus.setText(str("Allowed"))
        Allow_Func = self.VH_dll.restorefile
        Allow_Func.argtypes = [ctypes.c_char_p];
        Allow_Func.restype = None
        
        path = self.widget.fileName.text()
        Allow_Func(path.encode())
        self.widget.allowFileBtn.hide()
        self.widget.deleteFileBtn.hide()
    
    def on_deleteFileBtn_toggled(self):
        self.widget.fileStatus.setText(str("Deleted"))
        Delete_Func = self.VH_dll.deletefile
        Delete_Func.argtypes = [ctypes.c_char_p]
        Delete_Func.restype = None
        
        path = self.widget.fileName.text()
        Delete_Func(path.encode())
        self.widget.allowFileBtn.hide()
        self.widget.deleteFileBtn.hide()


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
        self.container_widget = QWidget()
        self.ui.scrollArea.setWidget(self.container_widget)
        self.container_layout = QVBoxLayout(self.container_widget)
        self.container_layout.setAlignment(Qt.AlignTop)
    
    def add_to_scorll_area(self,widget):
         self.container_layout.insertWidget(0, self.widget)
    
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
        self.ui.stackedWidget.setCurrentIndex(2)
    def on_helpBtn_clicked(self):
        self.color_all_button_back()
        self.ui.stackedWidget.setCurrentIndex(3)     

    def on_filePathBtn_toggled(self):
        self.open_file_dialog()   

    def on_folderPathBtn_toggled(self):
        self.open_folder_dialog()           
    
    def scan_result_update(self,time,threats,scanned):
        self.ui.scanTime.setText("Last Scan Time: " + time)
        self.ui.numScanned.setText(scanned + " Files Scanned")
        self.ui.numThreats.setText(threats + " Threats Found")        

def start_GUI():
    app = QApplication(sys.argv)
    window = AV_Application()
    window.show()   

    return app,window







