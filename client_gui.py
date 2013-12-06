#Note: tkinter import statement works for Python 3 ONLY
import tkinter

################################################################
# WARNING: ONLY USE THIS IF YOU ARE RUNNING PYTHON 3 or Higher
#
#################################################################
class ClientGUI(tkinter.Tk):
    def __init__(self,parent):
        tkinter.Tk.__init__(self,parent)
        self.parent = parent
        self.initialize()

    def initialize(self):
        self.grid()
        
if __name__ == "__main__":
    client = ClientGUI(None)
    client.title('Client')
    client.mainloop()
