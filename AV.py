from GUI import AV_GUI
import WindowsMalwareDetection.Code.PE_Main
import sys,os




if __name__ == "__main__":

    app,window = AV_GUI.start_GUI()
    
    sys.exit(app.exec_()) 
