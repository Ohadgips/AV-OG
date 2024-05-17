from .AV_GUI import Ui_AV_App
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton, QWidget,QFileDialog
import sys,os
#from . import AV_Icons_rc


def get_default_download_folder():
    # Get the user's home directory
    home_dir = os.path.expanduser("~")

    # Determine the default download directory based on the platform
   
    if os.name == 'nt':  # Windows
        return os.path.join(home_dir, 'Downloads')
    else:
        return home_dir

class AV_Application(QMainWindow):
    start_other_function = pyqtSignal()
    def __init__(self):
        super(AV_Application,self).__init__()

        self.ui = Ui_AV_App()
        self.ui.setupUi(self) 
        self.ui.stackedWidget.setCurrentIndex(5)
        self.ui.scanBtn.setEnabled(False)
        self.ui.scanBtn.hide()
        self.scanBtn = self.ui.scanBtn
        self.filePath = self.ui.filePath
    
    
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
        self.ui.settingsBtn.setStyleSheet(default)
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
    
    def on_settingsBtn_clicked(self):
        self.color_all_button_back()
        self.turn_button_on(self.ui.settingsBtn)
        self.ui.stackedWidget.setCurrentIndex(2)
    
    def on_infoBtn_clicked(self):
        self.color_all_button_back()
        self.ui.stackedWidget.setCurrentIndex(4)
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


