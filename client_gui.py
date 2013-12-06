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

        #Buttons and textfields
        self.uploadfilecontent= StringVar()
        uploadfilelabel = Label(self.parent, text="Upload File:")
        uploadfilelabel.grid(row=0)
        self.uploadfiletextfield = Entry(self.parent, textvariable=self.uploadfilecontent)
        self.uploadfiletextfield.grid(row=0,column=1)
        uploadfilebutton = Button(self.parent, text="Open...", command=self.fileUpload)
        uploadfilebutton.grid(row=0,column=2)

        self.uploaddircontent = StringVar()
        uploaddirlabel = Label(self.parent, text="Upload Directory:")
        uploaddirlabel.grid(row=1)
        uploaddirtextfield = Entry(self.parent, textvariable=self.uploaddircontent)
        uploaddirtextfield.grid(row=1,column=1)
        uploaddirbutton = Button(self.parent, text="Open...", command=self.dirUpload)
        uploaddirbutton.grid(row=1,column=2)

        self.retrievefilecontent = StringVar()
        retrievefilelabel = Label(self.parent, text="Retrieve File:")
        retrievefilelabel.grid(row=2)
        retrivefiletextfield = Entry(self.parent, textvariable=self.retrievefilecontent)
        retrivefiletextfield.grid(row=2,column=1)
        retrievefilebutton = Button(self.parent, text="Open...", command=self.fileRetrieve)
        retrievefilebutton.grid(row=2,column=2)

        self.retrievedircontent = StringVar()
        retrievedirlabel = Label(self.parent, text="Retrieve Directory")
        retrievedirlabel.grid(row=3)        
        retrivedirtextfield = Entry(self.parent, textvariable=self.retrievedircontent)
        retrivedirtextfield.grid(row=3,column=1)
        retrievedirbutton = Button(self.parent, text="Open...", command=self.dirRetrieve)
        retrievedirbutton.grid(row=3,column=2)        
        
    def onExit(self):
        self.quit()

    def fileUpload(self):
        filename = filedialog.askopenfilename()
        self.uploadfilecontent.set(filename)

    def dirUpload(self):
        filename = filedialog.askdirectory()
        self.uploaddircontent.set(filename)
        
    def dirRetrieve(self):
        filename = filedialog.askopenfilename(filetypes=[("Client Logs","*.clog")])
        self.retrievedircontent.set(filename)

    def fileRetrieve(self):
        filename = filedialog.askopenfilename(filetypes=[("Client Logs","*.clog")])
        self.retrievefilecontent.set(filename)
        
if __name__ == "__main__":
    root = Tk()
    root.geometry("500x500")
    client = ClientGUI(root)
    client.mainloop()
