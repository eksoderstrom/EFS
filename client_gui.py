#Note: tkinter import statement works for Python 3 ONLY
from tkinter import *
from tkinter import filedialog
import client
import os, xmlrpc.client

################################################################
# WARNING: ONLY USE THIS IF YOU ARE RUNNING PYTHON 3 or Higher
# It will not run on earlier versions of Python. Python < 3 uses
# 'Tkinter' as opposed to 'tkinter'
#
# Developer/Recommended Python Version: 3.3.0
#################################################################

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32

#################################################################
# GUI For the Encrypted File System.
# Basic Prototype
#################################################################
class ClientGUI(Frame):
    def __init__(self, parent=None):
        Frame.__init__(self, parent)
        self.parent = parent
        self.parent.title('Camel Client (CC v1.0)')
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

    def verify_fail(self):
        verify_fail = Toplevel()
        verify_fail.title("Verify Warning")
        warning = Label(verify_fail, text="Cannot verify this file. It has been corrupted. Download new copy?")
        warning.grid(row=0)        
        okay = Button(verify_fail, text="Download",command=self.generate_rsa_key_pair)
        okay.grid(row=1)
        cancel = Button(verify_fail, text="Cancel",command=verify_fail.destroy)
        cancel.grid(row=1,column=2,sticky=W)
        
    def ask_share_info(self):
        self.share = Toplevel()
        self.share.title("Share")

        msg = Label(self.share, text="Requires username of person and client log of file.")
        msg.grid(row=0)
        self.other_username = StringVar()
        usernamelabel = Label(self.share, text="Username: ")
        usernamelabel.grid(row=1)
        usernametext = Entry(self.share, textvariable=self.other_username)
        usernametext.grid(row=1,column=1)
        self.other_pubkey = StringVar()
        pubkeylabel = Label(self.share, text="Public Key: ")
        pubkeylabel.grid(row=2)
        pubkeytext = Entry(self.share, textvariable=self.other_pubkey)
        pubkeytext.grid(row=2,column=1)
        retrievefilebutton = Button(self.share, text="Browse...", command=self.fileRetrieve)
        retrievefilebutton.grid(row=2,column=2)        
        self.share_file = StringVar()
        filelabel = Label(self.share, text="File: ")
        filelabel.grid(row=3)
        filetext = Entry(self.share, textvariable=self.share_file)
        filetext.grid(row=3,column=1)
        retrievefilebutton = Button(self.share, text="Browse...", command=self.fileRetrieve)
        retrievefilebutton.grid(row=3,column=2)
        readpermission = IntVar()
        writepermission = IntVar()
        readbutton = Checkbutton(self.share, text="Read", variable=readpermission)
        readbutton.grid(row=4)
        writebutton = Checkbutton(self.share, text="Write", variable=writepermission)
        writebutton.grid(row=4, column=1)
        sendfilebutton = Button(self.share, text="Share", command=self.shareFile)
        sendfilebutton.grid(row=5, sticky=W+E+N+S, padx=5,pady=5,columnspan=2)
        
    def initialize(self):

        #Menu
        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)
        fileMenu = Menu(menubar)
        fileMenu.add_command(label="Exit", command=self.onExit)
        menubar.add_cascade(label="File", menu=fileMenu)
        optMenu = Menu(menubar)
        optMenu.add_command(label="Export RSA Public Key", command=self.onExit)
        optMenu.add_command(label="Import RSA Keys...", command=self.onExit)
        menubar.add_cascade(label="Options", menu=optMenu)
        helpMenu = Menu(menubar)
        helpMenu.add_command(label="About", command=self.onExit)
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
        self.readwrite_text = StringVar()
        self.readwrite_text.set("Not Generated")
        readwritekeylabel = Label(self.parent, text="R/W (Owner):")
        readwritekeylabel.grid(row=2)
        readwritekeytextfield = Entry(self.parent, state='readonly', textvariable=self.readwrite_text)
        readwritekeytextfield.grid(row=2, column=1)
        readwritebutton = Button(self.parent, text="Generate", command=self.generate_rsa_file_key)
        readwritebutton.grid(row=2,column=2)
        
        #Upload and Retrival 
        self.uploadfilecontent= StringVar()
        uploadfilelabel = Label(self.parent, text="Upload File:")
        uploadfilelabel.grid(row=3)
        self.uploadfiletextfield = Entry(self.parent, textvariable=self.uploadfilecontent)
        self.uploadfiletextfield.grid(row=3,column=1)
        uploadfilebutton = Button(self.parent, text="Browse...", command=self.getfilename)
        uploadfilebutton.grid(row=3,column=2)
        sendfilebutton = Button(self.parent, text="Submit", command=self.fileUpload)
        sendfilebutton.grid(row=3,column=3, sticky=W+E+N+S, padx=5,pady=5,columnspan=2)
        
        self.uploaddircontent = StringVar()
        uploaddirlabel = Label(self.parent, text="Upload Directory:")
        uploaddirlabel.grid(row=4)
        uploaddirtextfield = Entry(self.parent, textvariable=self.uploaddircontent)
        uploaddirtextfield.grid(row=4,column=1)
        uploaddirbutton = Button(self.parent, text="Browse...", command=self.dirUpload)
        uploaddirbutton.grid(row=4,column=2)
        senddirbutton = Button(self.parent, text="Submit", command=self.fileUpload)
        senddirbutton.grid(row=4,column=3, sticky=W+E+N+S, padx=5,pady=5,columnspan=2)
        
        self.retrievefilecontent = StringVar()
        retrievefilelabel = Label(self.parent, text="Retrieve File:")
        retrievefilelabel.grid(row=5)
        retrivefiletextfield = Entry(self.parent, textvariable=self.retrievefilecontent)
        retrivefiletextfield.grid(row=5,column=1)
        retrievefilebutton = Button(self.parent, text="Browse...", command=self.fileRetrieve)
        retrievefilebutton.grid(row=5,column=2)
        retrievefilebutton = Button(self.parent, text="Retrieve", command=self.fileRetrieveServer)
        retrievefilebutton.grid(row=5,column=3, sticky=W+E+N+S, padx=5,pady=5,columnspan=2)
        
        self.retrievedircontent = StringVar()
        retrievedirlabel = Label(self.parent, text="Retrieve Directory")
        retrievedirlabel.grid(row=6)        
        retrivedirtextfield = Entry(self.parent, textvariable=self.retrievedircontent)
        retrivedirtextfield.grid(row=6,column=1)
        retrievedirbutton = Button(self.parent, text="Browse...", command=self.dirRetrieve)
        retrievedirbutton.grid(row=6,column=2)
        retrievedirbutton = Button(self.parent, text="Retrieve", command=self.fileRetrieveServer)
        retrievedirbutton.grid(row=6,column=3, sticky=W+E+N+S, padx=5,pady=5,columnspan=2)

        self.sharebutton = Button(self.parent, text="Share", fg="Orange",command=self.share, height=4, width=10)
        self.sharebutton.grid(row=7)
        
        root.lower()
        self.login_msg(self)

##################################################
# Callback Methods
#
#
##################################################
        
    def onExit(self):
        self.quit()

    def share(self):
        self.ask_share_info()

    def shareFile(self):
        self.shareFile = Toplevel()
        self.shareFile.title("Share")
        self.shareFile.geometry('100x100')
        msg = Label(self.shareFile, text="Not in demo.")
        msg.grid(row=0)
        self.share.destroy()
        msgbutton = Button(self.shareFile, text="Close", command=self.shareFile.destroy)
        msgbutton.grid(row=1)        

    def login(self):
        self.s = xmlrpc.client.ServerProxy('https://' + self.username.get() + ':' + self.password.get() + '@localhost:443')
        try:
            self.s.echo("login")
        except xmlrpc.client.ProtocolError as err:
            print("invalid credentials, please login")        
        
        self.loadRSAKeyPair(self.username)
        self.dict = client.retrieve_database(self.username.get())

    def register(self):
        pass

    def fileUpload(self):
        """ Sends a file to server For further information,
            look at send_to_server in client.py.
        """
        client.send_to_server(self.username.get(), self.uploadfilecontent.get(), self.aes_key, self.s, self.dict)
        success = Toplevel()
        msg = Label(success, text="File Successfully Uploaded to Server")
        msg.grid(row=0)
        msgbutton = Button(success, text="Thanks", command=success.destroy)
        msgbutton.grid(row=1)
        
        
    def fileRetrieveServer(self):
        verify = client.retrieve_from_server(self.retrievefilecontent.get(), self.s, self.dict)
        if verify == False:
            self.verify_fail()
        else:
            success = Toplevel()
            msg = Label(success, text="File Successfully Retrieved From Server")
            msg.grid(row=0)
            msgbutton = Button(success, text="Thanks", command=success.destroy)
            msgbutton.grid(row=1)
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

    def generate_rsa_file_key(self):
        self.readwrite_text.set("Generated")
        self.readwritekey = client.generate_rsa_key(RSA_KEY_SIZE)
        
if __name__ == "__main__":
    root = Tk()
    root.geometry("390x300")
    clientgui = ClientGUI(root)
    clientgui.mainloop()
