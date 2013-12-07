#Note: tkinter import statement works for Python 3 ONLY
from tkinter import *
import client
import os

################################################################
# WARNING: ONLY USE THIS IF YOU ARE RUNNING PYTHON 3 or Higher
# It will not run on earlier versions of Python. Python < 3 uses
# 'Tkinter' as opposed to 'tkinter'
#
# Developer/Recommended Python Version: 3.3.0
#################################################################

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 256

#################################################################
# GUI For the Encrypted File System.
# Basic Prototype
#################################################################
class ClientGUI(Frame):
    def __init__(self, parent=None):
        Frame.__init__(self, parent)
        self.parent = parent
        self.parent.title('Client v1.0')
        self.initialize()

    def login_msg(self, parent):
        self.logintop = Toplevel(self)
        self.logintop.title('Login Screen')
        self.logintop.geometry("380x100")
        msg = Label(self.logintop, text="Input username and password.")
        msg.grid(row=0)

        self.username = StringVar()
        usernamelabel = Label(self.logintop, text="Username:")
        usernamelabel.grid(row=1,sticky=W)
        usernametextfield = Entry(self.logintop, textvariable=self.username)
        usernametextfield.grid(row=1, column=1, sticky=W)
        self.password = StringVar()
        passwordlabel = Label(self.logintop, text="Password:")
        passwordlabel.grid(row=2,sticky=W)
        passwordtextfield = Entry(self.logintop, show="*", textvariable=self.password)
        passwordtextfield.grid(row=2, column=1)

        registerbutton = Button(self.logintop, text='Register',command=parent.register)
        registerbutton.grid(row=3,sticky=E)
        loginbutton = Button(self.logintop, text='Login',command=parent.login)
        loginbutton.grid(row=3,column=1)
        cancelbutton = Button(self.logintop, text='Cancel',
                                command=self.logintop.destroy)
        cancelbutton.grid(row=3,column=2,sticky=W)
        root.lift()

    def gen_rsa_pair_msg(self):
        self.rsa_msg = Toplevel()
        self.rsa_msg.title("RSA Key-Pair Warning")

        warning = Label(self.rsa_msg, text="Cannot find any RSA-key pair for this user. Generate new key-pair?")
        warning.grid(row=0)
        okay = Button(self.rsa_msg, text="Generate",command=self.generate_rsa_key_pair)
        okay.grid(row=1)
        cancel = Button(self.rsa_msg, text="Ignore Warning",command=self.rsa_msg.destroy)
        cancel.grid(row=1,column=2,sticky=W)
        
    def initialize(self):
        
        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)
        fileMenu = Menu(menubar)
        fileMenu.add_command(label="Exit", command=self.onExit)
        menubar.add_cascade(label="File", menu=fileMenu)
        aesMenu = Menu(menubar)
        menubar.add_cascade(label="AES Keys", menu=aesMenu)
        rsaMenu = Menu(menubar)
        menubar.add_cascade(label="RSA Key", menu=rsaMenu)
        helpMenu = Menu(menubar)
        menubar.add_cascade(label="Help", menu=helpMenu)

        #Keys
        rsakeypairlabel = Label(self.parent, text="RSA Key Pair:")
        rsakeypairlabel.grid(row=0)
        self.rsakeypairstatuslabel = Label(self.parent, text="currently NOT loaded")
        self.rsakeypairstatuslabel.config(fg='red')
        self.rsakeypairstatuslabel.grid(row=0,column=1)
        readkeylabel = Label(self.parent, text="Current AES Key:")
        readkeylabel.grid(row=1)
        readkeybutton = Button(self.parent, text="Generate", command=self.generate_aes_key)
        readkeybutton.grid(row=1,column=2)
        self.aes_key_text = StringVar()
        readkeytextfield = Entry(self.parent, state='readonly',textvariable=self.aes_key_text)
        readkeytextfield.grid(row=1, column=1)
        readwritekeylabel = Label(self.parent, text="EXTRA FEATURE IGNORE!!!:")
        readwritekeylabel.grid(row=2)
        readwritekeytextfield = Entry(self.parent, state='readonly')
        readwritekeytextfield.grid(row=2, column=1)
        
        #Upload and Retrival 
        self.uploadfilecontent= StringVar()
        uploadfilelabel = Label(self.parent, text="Upload File:")
        uploadfilelabel.grid(row=3)
        self.uploadfiletextfield = Entry(self.parent, textvariable=self.uploadfilecontent)
        self.uploadfiletextfield.grid(row=3,column=1)
        uploadfilebutton = Button(self.parent, text="Open...", command=self.getfilename)
        uploadfilebutton.grid(row=3,column=2)
        sendfilebutton = Button(self.parent, text="Submit", command=self.fileUpload)
        sendfilebutton.grid(row=3,column=3, sticky=W+E+N+S, padx=5,pady=5,columnspan=2)
        
        self.uploaddircontent = StringVar()
        uploaddirlabel = Label(self.parent, text="Upload Directory:")
        uploaddirlabel.grid(row=4)
        uploaddirtextfield = Entry(self.parent, textvariable=self.uploaddircontent)
        uploaddirtextfield.grid(row=4,column=1)
        uploaddirbutton = Button(self.parent, text="Open...", command=self.dirUpload)
        uploaddirbutton.grid(row=4,column=2)

        self.retrievefilecontent = StringVar()
        retrievefilelabel = Label(self.parent, text="Retrieve File:")
        retrievefilelabel.grid(row=5)
        retrivefiletextfield = Entry(self.parent, textvariable=self.retrievefilecontent)
        retrivefiletextfield.grid(row=5,column=1)
        retrievefilebutton = Button(self.parent, text="Open...", command=self.fileRetrieve)
        retrievefilebutton.grid(row=5,column=2)

        self.retrievedircontent = StringVar()
        retrievedirlabel = Label(self.parent, text="Retrieve Directory")
        retrievedirlabel.grid(row=6)        
        retrivedirtextfield = Entry(self.parent, textvariable=self.retrievedircontent)
        retrivedirtextfield.grid(row=6,column=1)
        retrievedirbutton = Button(self.parent, text="Open...", command=self.dirRetrieve)
        retrievedirbutton.grid(row=6,column=2)
        
        root.lower()
        self.login_msg(self)

##################################################
# Callback Methods
#
#
##################################################
        
    def onExit(self):
        self.quit()

    def login(self):
        self.loadRSAKeyPair(self.username)

    def register(self):
        pass

    def fileUpload(self):
        """ Actually does a few things before
            uploading the file to the server.
            First, we have to add a file header
            to the file, if it doesn't have one yet.
            We can check for this with its client logs,
            which the client can find out from a dictionary
            or if the user specifies this.
        """
        pass

    def dirUpload(self):
        filename = filedialog.askdirectory()
        self.uploaddircontent.set(filename)
        
    def getfilename(self):
        filename = filedialog.askopenfilename()
        self.uploadfilecontent.set(filename)
        
    def dirRetrieve(self):
        filename = filedialog.askopenfilename(filetypes=[("Client Logs","*.clog")])
        self.retrievedircontent.set(filename)

    def fileRetrieve(self):
        filename = filedialog.askopenfilename(filetypes=[("Client Logs","*.clog")])
        self.retrievefilecontent.set(filename)

    def generate_aes_key(self):
        self.aes_key = client.generate_nonce(AES_KEY_SIZE)
        self.aes_key_text.set(str(self.aes_key))

    def loadRSAKeyPair(self, username):
        ''' Checks a public-key pair exists for
            the user. If not, ask the user if they
            would like to generate a new rsa-key pair

            username: used to find the corresponding
            file that contains the rsa-key pair
    
        '''
        filename = username.get() + '.pri'
        if os.path.isfile(filename):
            self.key = client.load_rsa_key(filename)
            self.rsakeypairstatuslabel['text'] = 'currently loaded'
            self.rsakeypairstatuslabel.config(fg='green')
            self.rsakeypairstatuslabel.grid(row=0,column=1)
        else:
            self.gen_rsa_pair_msg()

        self.logintop.destroy()

    def generate_rsa_key_pair(self):
        """ Generates a public-key pair for user
        """
        self.key = client.generate_rsa_key(RSA_KEY_SIZE)
        filename = self.username.get() + '.pri'
        client.export_rsa_key_pair(filename, self.key)
        rsa = Toplevel()
        rsa.title("RSA Key-Pair")
        self.rsakeypairstatuslabel['text'] = 'currently loaded' 
        self.rsakeypairstatuslabel.config(fg='green')
        self.rsakeypairstatuslabel.grid(row=0,column=1)
        msg = Label(rsa, text="Key-Pair Saved in Folder")
        msg.grid(row=0)
        msgbutton = Button(rsa, text="Thanks", command=rsa.destroy)
        msgbutton.grid(row=1)
        self.rsa_msg.destroy()
        
if __name__ == "__main__":
    root = Tk()
    root.geometry("390x300")
    clientgui = ClientGUI(root)
    clientgui.mainloop()
