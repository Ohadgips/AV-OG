from AV_GUI import Ui_AV_App
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton, QWidget
import sys

class AV_Application(QMainWindow):
    global ui
    start_other_function = pyqtSignal()
    def __init__(self):
        super(AV_Application,self).__init__()

        self.ui = Ui_AV_App()
        self.ui.setupUi(self) 
        self.on_theatsBtn_clicked()



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
        self.ui.stackedWidget.setCurrentIndex(4)
    def on_helpBtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(3)     



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AV_Application()

    window.show()    

    sys.exit(app.exec_())
