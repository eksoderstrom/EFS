#Note: tkinter import statement works for Python 3 ONLY
from tkinter import *

################################################################
# WARNING: ONLY USE THIS IF YOU ARE RUNNING PYTHON 3 or Higher
#
#################################################################
class ClientGUI(Frame):
    def __init__(self, parent=None):
        Frame.__init__(self, parent)
        self.parent = parent
        self.initialize()

    def initialize(self):
        self.parent.title('Client')
        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)
        
        fileMenu = Menu(menubar)
        fileMenu.add_command(label="Exit", command=self.onExit)
        menubar.add_cascade(label="File", menu=fileMenu)
        exportMenu = Menu(menubar)
        menubar.add_cascade(label="Export Key", menu=exportMenu)
        importMenu = Menu(menubar)
        menubar.add_cascade(label="Import Key", menu=importMenu)

        uploadfiletextfield = Entry(self.parent)
        uploadfiletextfield.pack(side=LEFT)
        uploadfilebutton = Button(self.parent, text="Upload File", command=self.fileUpload)
        uploadfilebutton.pack(side=LEFT)
        uploaddirtextfield = Entry(self.parent)
        uploaddirtextfield.pack(side=LEFT)
        uploaddirbutton = Button(self.parent, text="Upload Directory", command=self.dirUpload)
        uploaddirbutton.pack(side=LEFT)
    def onExit(self):
        self.quit()

    def fileUpload(self):
        filename = filedialog.askopenfilename()

    def dirUpload(self):
        filename = filedialog.askdirectory()

        
if __name__ == "__main__":
    root = Tk()
    root.geometry("500x500")
    client = ClientGUI(root)
    client.mainloop()
