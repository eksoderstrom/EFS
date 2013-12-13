import xmlrpc.client, random, struct, os, hashlib, sys, base64
from Crypto.Cipher import AES
#RSA imports
import Crypto.PublicKey.RSA as RSA
import Crypto.PublicKey.DSA as DSA
import Crypto.Random.OSRNG.posix as Nonce
import Crypto.Random.random as SuperRandom
import Crypto.Hash.SHA256 as SHA256
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import Crypto.Random as Random
import Crypto.Random.random as random
#MAC import
import hmac
import ntpath
import pickle
#custom imports
from client_classes import FileHeader
from client_classes import AccessBlock
#regex import
import re

import datetime
INSUFFICIENT_PRIVILEGE_EXCEPTION = -2

s = xmlrpc.client.ServerProxy('https://localhost:443')

#Macros
AES_KEY_SIZE = 32
RSA_KEY_SIZE = 2048
FILE_HEADER_NONCE_SIZE = 32


class Client():
    def __init__(self):
        self.s = xmlrpc.client.ServerProxy('https://localhost:443')
        self.username = None
        self.password = None
        self.wd = None

    """
    The following functions are exposed via the shell. They pertain mainly to filesystem navigation and user registration / authentication.
    """

    def echo(self, arg):
        try:
            print(s.echo(arg))
        except:
            print("echo failed")

    def login(self, uname, passwd):
        try:
            if s.login(uname, passwd) == 'ok':
                self.username = uname
                self.password = passwd
                self.wd = '/' + uname + "/"
                print("successfully logged in as " + self.username)
            else:
                print("login unsuccessful")
        except:
            print("Login as " + uname + " failed")

    def logout(self):
        name = self.username
        self.username = None
        self.password = None
        print("logged out " + name)

    def whoami(self):
        if self.username:
            print(self.username)
        else:
            print("not logged in")

    def register(self, username, password):
        if self.username == None:
            if self.s.register(username, password) == 'ok':
                print("registration success")
            else:
                print("username taken")
        else:
            print("logout before registering as another user")


    def ls(self, path='None'):
        if path=='None':
            path = self.wd
        try:
            print(s.ls(self.username, self.password, path))
        except:
            print('no such file or directory')

    def cd(self, path):
        if path[0] != '/':
            try:
                if path in s.ls(self.username, self.password, self.wd):
                    self.wd = self.wd + path
            except:
               print("invalid directory name")
        else:
            pass

    def pwd(self):
        print(self.wd)


    def share_read(self, path, recipient):
        try:
            if s.share_read(self.username, self.password, path, recipient):
                print('successfully shared read access to ' + path + ' with ' + recipient)
            else:
                print('failed to share')
        except:
            print('connection error')

    def share_write(self, path, recipient):
        try:
            if s.share_write(self.username, self.password, path, recipient):
                print('successfully shared write access to ' + path + ' with ' + recipient)
            else:
                print('failed to share')
        except:
            print('connection error')
            

    def get_file(self, path, dst):
        try:
            arg = s.send_file_to_client(self.username, self.password, path)
            if arg:
                with open(dst, 'wb+') as handle:
                    handle.write(arg.data)
                print('successfully retrieved ' + path)
            else:
                print("permission denied")
        except:
            print("get file failed")

    def rm(self, filename):
        try:
            if s.rm(self.username, self.password, filename)==True:
                print("filed removed")
        except:
            print('rm failed')

    """
    Private methods not exposed through the shell
    """
    def xfer(self, filename, dst):
        print('transfering ' + filename + ' to ' + dst)
        try:
            with open(filename, "rb") as handle:
                binary_data = xmlrpc.client.Binary(handle.read())
            ret = s.receive_file(self.username, self.password, binary_data, dst)
            if ret == True:
                print("Successfully uploaded file " + filename)
            if ret == INSUFFICIENT_PRIVILEGE_EXCEPTION:
                print("insufficient file privileges")
        except:
            print("File upload failed")

    """
    cryptographic functions
    """


    """
    unimplemented functions
    """

    def mkdir(self, path):
        if path[0] == '/':
            p = re.split('/',path)
            if p[1] == self.username:
                s.mkdir(self.username, self.password, path)
            else:
                print('you don\'t have permission to access that directory')
        else:
            p = re.split('/',self.wd)
            if (p[1] == self.username):
                s.mkdir(self.username, self.password, self.wd + path)
            else:
                print('you don\'t have permission to access that directory')

    def create(self, source, dst):
        enc_file = create_file(self.username, source)
        self.xfer(os.path.abspath(enc_file), dst + enc_file)
        self.xfer(os.path.abspath(enc_file + '.clog'), dst + enc_file + '.clog')
        print('file is encrypted as:' + enc_file)

c = Client()

#########################################################
# Shell 
#
#########################################################
def set_proxy(proxy):
    global s 
    s = xmlrpc.client.ServerProxy(proxy)
    print("s set to " + proxy)

def rm(path):
    try:
        s.rm(c.username, c.password, path)
    except xmlrpc.client.ProtocolError as err:
        print("invalid credentials")

def xfer(filename, dst):
    key = generate_aes_key()
    add_file_header(filename, key)
    new_filename = filename + '.fh'
    encrypt_file(new_filename, key)
    with open(new_filename+".encrypted", "rb") as handle:
        binary_data = xmlrpc.client.Binary(handle.read())
    s.receive_file(binary_data, dst)
 
def get_file(path, dst):
    arg = s.send_file_to_client(path)
    with open(dst, 'wb') as handle:
        handle.write(arg.data)
    



    

def mv(source, dst):
    pass

def enc(fn):
    encrypt_file(new_in_filepath)

def dec(fn):
    decrypt_file(fn, "/Users/eks/Desktop/decrypted")
    
#########################################################
# Key Generation Methods
#
#########################################################
def generate_nonce(size):
    """ Generates a random value using a secure
        random number generator from os.urandom

        size: number of bytes
    """
    #return Nonce.new().read(size) -> this cannot be used by windows
    return os.urandom(size)
def generate_dsa_key(size):
    """ Generate a fresh, new, DSA key object
        where size is the size of the key object
    """
    key = DSA.generate(size)
    return key

def export_dsa_public(username, key):
    filepath = username + '.dsapub'
    with open(filepath, 'wb') as outfile:
        pickle.dump(key.publickey(), outfile, -1)

def export_dsa(username, key):
    filepath = username + '.dsa'
    with open(filepath, 'wb') as outfile:
        pickle.dump(key, outfile, -1)

def sign_with_dsa(aes_key, dsa_key, filepath):
    """ Sign a file with DSA

        filepath: encrypted data
    """
    filehash = SHA256.new()
    chunksize=64*1024
    with open(filepath, 'rb') as infile:
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            filehash.update(chunk)
    k = SuperRandom.StrongRandom().randint(1, dsa_key.q-1)
    sig = dsa_key.sign(filehash.digest(), k)
    return sig

def verify_with_dsa(key, filehash, sig):
    return key.verify(filehash.digest(), sig)
def generate_rsa_key(size):
    """ Generate a fresh, new RSA key object
    where nonce is the random function and size is
    the size of the key object
    """
    nonce = os.urandom
    key = RSA.generate(size, nonce)
    return key

def encrypt_aes_key(public_rsa_key, aes_key):
    """ Encrypts AES key with another
        user's public key

        public_rsa_key: public key of person
    """
    ciphertext = public_rsa_key.encrypt(aes_key, None) #returns (ciphertext, None)
    ciphertext = ciphertext[0]
    return ciphertext

def decrypt_aes_key(private_rsa_key, encrypted_aes_key):
    """ Decrypts AES key with user's private
        key

        private_rsa_key: user's private rsa key
        encrypted_aes_key: 
    """
    decrypted_aes_key = private_rsa_key.decrypt(message)
    return decrypted_aes_key

def generate_aes_key():
    key = generate_nonce(AES_KEY_SIZE)
    return key

def generate_mac(key, filepath):
    """ Generates a mac
        key: AES key
        filepath: name of file to hmac
    """
    mac = hmac.new(key, None, hashlib.sha256)
    chunksize=64*1024
    with open(filepath, 'rb') as infile:
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            mac.update(chunk)
    return mac.hexdigest()

def generate_mac_for_filename(key, filename):
    mac = hmac.new(key, str.encode(filename), hashlib.sha256)
    return mac.hexdigest()

def export_rsa_key_pair(filepath, key, passphrase=None):
    """ Save a copy of our rsa key pair
        Treat this as saving the private
        key. Do not distribute this file.
    """
    try:
        f = open(filepath, 'wb')
        f.write(key.exportKey())
        f.close()
    except IOError as e:
        print(e)

def export_rsa_public_key(filepath, key):
    """ Saves a copy of the public key
        only.

        filepath:
        key: RSA key object
    """
    filepath = filepath + '.pub'
    try:
        f = open(filepath, 'wb')
        f.write(key.publickey().exportKey())
        f.close()
    except IOError as e:
        print(e)
        
def load_rsa_key(filepath, passphrase=None):
    """ Retrieve our rsa key from file

        filepath: name of file containing
        public-private key pair
    """
    try:
        f = open(filepath)
        key = RSA.importKey(f.read())
        f.close()
        return key
    except IOError as e:
        print (e)

def save_key_pair(filepath, rsa_key):
    """ Saves the user's public-private
        key pair for later retrieval.

        filepath: name of file where
        keys will be stored. Two files
        will be made with extensions
        '.pub' and '.pri' for public
        and private keys, respectively.

        rsa_key: RSA key object
    """
    export_rsa_key_pair(filepath)
    export_rsa_public_key(filepath)

####################################################
# A set of methods used to verify that a file has
# not been modified by somebody malicious
#####################################################

def verify_file_signature(sig, file_dsa_key, filepath):
    filehash = SHA256.new()
    chunksize=64*1024
    with open(filepath, 'rb') as infile:
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            filehash.update(chunk)
    return file_dsa_key.verify(filehash.digest(), sig)

def verify_log_signature(sig, owner_dsa_key, log):
    del log['log_signature']
    picklelog = pickle.dumps(log)
    h = SHA256.new()
    h.update(picklelog)
    return owner_dsa_key.verify(h.digest(), sig)    

########################################################
# These methods help with encrypting, decrypting, sending
# and retrieving files and directories
########################################################

def create_file(owner, filename):
    """ This method creates a file on the server.
        
    """
    fek = generate_aes_key()
    fsk_dsa_key = generate_dsa_key(1024)
    print('Create: ' + filename)
    
    new_filename = filename + '.fh'
    
    #RPC Call here
    encrypted_name = generate_mac_for_filename(fek, get_filename_from_filepath(new_filename))
    
    add_file_header(filename, fek, fsk_dsa_key)
    encrypt_file(new_filename, fek, encrypted_name)
    #dst = dst + '/' + encrypted_name
    timestamp = datetime.datetime.utcnow()
    store_log(owner, fek, fsk_dsa_key, timestamp, filename, encrypted_name)
   # with open(final_filename, "rb") as handle:
   #     binary_data = xmlrpc.client.Binary(handle.read())
    print("encrypted: " + encrypted_name)
    return encrypted_name

def decrypt(username, owner, filename):
    in_filepath = filename + '.clog'
    with open(in_filepath, 'rb') as input:
        log = pickle.load(input)
        log_sig = pickle.load(input)
    with open(in_filepath, 'rb') as input:
        filehash = input.read(len(log))
    block = log[username]
    with open(owner + '.dsa', 'rb') as input:
        owner_dsa_key = pickle.load(input)
    #
    file_dsa_key = log['file_dsa_public']

    h = SHA256.new()
    h.update(filehash)
    verify_sig =  owner_dsa_key.verify(h.digest(), log_sig)

    key = RSA.importKey(open(username + '.pri').read())
    cipher = PKCS1_OAEP.new(key, SHA256.new())



    
    block.decrypt_permission_block(cipher)
    decrypt_file(filename, block.get_file_encryption_key(), filename + '.decrypted')
    fh = read_file_header(filename + '.decrypted')
    file_sig = fh.get_signature()
    remove_file_header(filename + '.decrypted')
    print('get: ' + fh.get_filename())


    os.rename(filename + '.decrypted.rfh', fh.get_filename())
    if verify_sig and verify_file_signature(file_sig, file_dsa_key, fh.get_filename()):
        return True
    return False

def write_file(username, filelog, filename):
    with open(filelog, 'rb') as input:
        log = pickle.load(input)

    
    block = log[username]
    block.decrypt_permission(cipher)
    file_aes_key = block.get_file_encryption_key()
    file_dsa_key = block.get_file_signature_key()

    add_file_header(filename, file_aes_key, file_dsa_key)
    encrypt_file(filename, file_aes_key, filelog[0:-5])
    
def share_file(username, password, other_username, client_log):
    pass

def share_directory(username, password, other_username, client_log):
    pass

def send_dir_to_server(username, directory, key, s, db):
    pass

def retrieve_dir_from_server(log_filepath, s, db):
    pass

def delete_file():
    pass

def rename_file():
    pass

def share_public_key():
    pass

def get_public_key():
    pass
        
def store_log(owner_username, fek, file_dsa_key, timestamp, filename, encrypted_name):
    """ Stores information about the file on the sever-side. Facilitates downloading of 
        associated data file. 
        username:
            username of owner
        file_aes_key: 
            aes key used to encrypt file
        file_dsa_key: 
            dsa key used to sign file            
        filename:
            Unecrypted name of the input file
        timestamp:
            The time when log file was last modified.         
        encrypted_name: 
            filepath on the encrypted file server
        
        out_filepath:
            '<in_filepath>.clog' will always be used
            unless user specifies a name.
    """
    out_filepath = encrypted_name + '.clog'
    owner_block = AccessBlock(fek, file_dsa_key);
    owner_mek = RSA.importKey(open(owner_username+ '.pub').read())
    hashfunc = SHA256.new()
    cipher = PKCS1_OAEP.new(owner_mek, hashfunc)
    owner_block.encrypt_permission_block(cipher)
    

    file_log_hash = SHA256.new()
    with open(owner_username + '.dsa', 'rb') as input:
        owner_msk = pickle.load(input)
    k = random.StrongRandom().randint(1,owner_msk.q-1)
    
    log = {'owner':owner_username, owner_username: owner_block, 'timestamp':timestamp, 'encrypted_name': encrypted_name, 'file_dsa_public': file_dsa_key.publickey()}

    with open(out_filepath, 'wb') as outfile:
        pickle.dump(log, outfile, -1)
    length = len(log)
    with open(out_filepath, 'rb') as outfile:
        picklelog = outfile.read(length)
    file_log_hash.update(picklelog)
    sig = owner_msk.sign(file_log_hash.digest(), k)
    with open(out_filepath, 'a+b') as outfile:
        pickle.dump(sig, outfile, -1)

class Test:

    def __init__(self, one, two):
        self.one = one
        self.two = two

def testAgain():
    key = generate_dsa_key(1024)
    test = Test(14, 'bottle')
    pickled = pickle.dumps(test)
    file = SHA256.new()
    file.update(pickled)
    k = random.StrongRandom().randint(1,key.q-1)
    sig = key.sign(file.digest(), k)

    with open('test.help', 'wb') as outfile:
        pickle.dump(test, outfile,-1)
        pickle.dump(sig, outfile, -1)
        #outfile.dump(test)
        #outfile.dump(sig)
    
    with open('test.help', 'rb') as input:
        obj = pickle.load(input)
        sigobj = pickle.load(input)

    objp = pickle.dumps(obj)
    fileobj = SHA256.new()
    fileobj.update(objp)
    return key.verify(fileobj.digest(), sig)

def testPickle():
    key = generate_dsa_key(1024)
    log = {'owner': 'hi', 'test': 'yes'}
    picklelog = pickle.dumps(log)
    file = SHA256.new()
    file.update(picklelog)
    k = random.StrongRandom().randint(1,key.q-1)
    sig = key.sign(file.digest(), k)
    
    log['sig'] = 'random'
    del log['sig']
    newh = pickle.dumps(log)
    h = SHA256.new()
    h.update(newh)
    pubkey = key.publickey()
    return pubkey.verify(h.digest(), sig)

#Taken from http://stackoverflow.com/questions/8384737/python-extract-file-name-from-path-no-matter-what-the-os-path-format
def get_filename_from_filepath(filepath):
    """ Retrieve filename from the filepath
        regardless of os.
    """
    head, tail = ntpath.split(filepath)
    return tail or ntpath.basename(head)

def add_file_header(in_filepath, fek, fsk):
    """ Adds a file header obj to the front of the file
        using Python's cpickle. 
        
        key: AES private key
    """
    out_filepath = in_filepath + '.fh'
    final_filename = out_filepath + '.encrypted'
    chunksize=64*1024
    sig = sign_with_dsa(fek, fsk, in_filepath)
    filename = get_filename_from_filepath(in_filepath)
    print("fileheader: "+ filename)
    file_header = FileHeader(filename, sig, 0)
    
    with open(in_filepath, 'rb') as infile:
        with open(out_filepath, 'wb') as outfile:

            pickle.dump(file_header, outfile, -1)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(chunk)
    outfile.close()
    return out_filepath

def read_file_header(in_filepath):
    """ Retrieves the file header object that is
        at the front of a file.
        Files read into this must have the
        extension '.fh'. Otherwise it will
        raise an error.
    """
        
    with open(in_filepath, 'rb') as input:
        file_header = pickle.load(input)
    return file_header

def remove_file_header(in_filepath):
    """ Given a file with a file header,
        remove the file header and return
        the original file.

        Basically, skips the FileHeader and
        just writes the contents of the
        original file.

        The file that is returned is the
        in_filepath name but with the extension
        '.fh' removed.

        CAREFUL. IT MAY OVERWRITE A FILE.
    """

    out_filepath = in_filepath + '.rfh'
    file_header = read_file_header(in_filepath)
    size_file_header = len(pickle.dumps(file_header))
    chunksize=64*1024
    with open(in_filepath, 'rb') as infile:
        with open(out_filepath, 'wb') as outfile:

            infile.read(size_file_header)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(chunk)
    
#Taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def encrypt_file(in_filepath, key, out_filepath=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filepath:
            Name of the input file

        out_filepath:
            If None, '<in_filepath>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
        

    if not out_filepath:
        out_filepath = in_filepath + '.encrypted'

    iv = bytes([ random.randint(0, 0xFF) for i in range(16)])
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filepath) 

    with open(in_filepath, 'rb') as infile:
        with open(out_filepath, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

#Taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def decrypt_file(in_filepath, key, out_filepath=None, chunksize=64*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filepath, if not supplied
        will be in_filepath without its last extension
        (i.e. if in_filepath is 'aaa.zip.enc' then
        out_filepath will be 'aaa.zip')
    """

    if not out_filepath:
        out_filepath = os.path.splitext(in_filepath)[0]
    #out_filepath = in_filepath
    with open(in_filepath, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filepath, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
#create('eric', 'C:/Users/Tiffany/Documents/GitHub/EFS/result.txt')
#get('eric', '284604.clog', 'result.txt.encrypted.fh')
