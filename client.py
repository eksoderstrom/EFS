import xmlrpc.client, random, struct, os, hashlib, sys, base64
from Crypto.Cipher import AES
#RSA imports
import Crypto.PublicKey.RSA as RSA
import Crypto.Random.OSRNG.posix as Nonce
#MAC import
import hmac
import ntpath

import pickle
"""TODO
    how to associate private keys with files
    """

s = xmlrpc.client.ServerProxy('http://localhost:8000')
key = '0123456789abcdef'    #Key should of course not be hard-coded, and should be stored on disk. placeholder for now

#Macros
AES_KEY_SIZE = 256
RSA_KEY_SIZE = 2048
FILE_HEADER_NONCE_SIZE = 32
WARNING = 'DO NOT DELETE THIS FILE. USED IN ENCRYPTED FILE SYSTEM.'

class Client():
    def __init__(self, username, password):
        pass
    
##########################################################################
# File Header 
# This class is used to keep track of certain parameters and is inserted
# at the front of the file we want to encrypt.
##########################################################################
class FileHeader():
    def __init__(self, nonce, mac, filename):
        """ The parameters stored in the file header
            are used for security and identification
            purposes.

            nonce: random number in bytes
            mac: used to verify the file
            filename:
        """
        self.nonce = nonce
        self.mac = mac
        self.filename = filename

    def get_nonce(self):
        return self.nonce

    def get_mac(self):
        return self.mac

    def get_filename(self):
        return self.filename

##########################################################################
# Client Log
# This class is used to store data abaout individual files on the client.
# The main reason why client log objects are used as opposed to simply
# writing the parameters of a file to the .clog file is because it is easier
# to extract information, especially if we choose to store more than one file
# in an client log file (ie: store a directory of files in a single client
# file)
##########################################################################
class ClientLog():
    def __init__(self, filename, nonce, key, gen_count):
        """ The parameters used here are for
            retrieval and identification
            purposes.

            nonce: random number in bytes
            mac: used to verify the file
            filename:
        """
        self.nonce = nonce
        self.key = key
        self.filename = filename
        self.gen_count = gen_count

    def get_nonce(self):
        return self.nonce

    def get_key(self):
        return self.key

    def get_gen_count(self):
        return self.gen_count

    def get_filename(self):
        return self.filename

#########################################################
# Shell 
#
#########################################################

def xfer(source):
    with open(source, "rb") as handle:
        binary_data = xmlrpc.client.Binary(handle.read())
    s.receive_file(binary_data)

def mv(source, dst):
    pass

def enc(fn):
    new_in_filepath = add_file_header(fn)
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
    

def send_public_key(key):
    key.publickey().exportKey()


####################################################
# A set of methods used to verify that a file has
# not been modified by somebody malicious
#####################################################

def verify_mac(file_header, key):
    pass

def verify_generation_count(file_header):
    pass

def verify_nonce_value(file_header):
    pass

def write_to_database(username, filename, client_log):
    """ To associate a file to a client log, we make note of it
        in a dictionary. This dictionary is written to a file
        everytime we make a modification. The file should not be
        modified by the user.

        username:

        filename: name of the file we are uploading

        client_log: name of the client log associated with filename
    """
    self.dict = {}
    filepath = username + '.db'
    if os.path.exists(filepath):
        with open(filepath, 'rb') as input:
            self.dict = pickle.load(input)
    self.dict[client_log] = filename

    with open(out_filepath, 'wb') as outfile:
        pickle.dump(self.dict, outfile, -1)

def retrive_file_from_client_log(log_filepath):
    """ The user retrieves a file from the server.
        The user specifies the client log file.

        log_filepath: filepath of client log associated
        with the file that the user wants to retrive from
        the server
    """
    assert len(log_filepath) > 5
    assert log_filepath[-5:] == '.clog'

    with open(log_filepath, 'rb') as input:
        log = pickle.load(input)

    #RPC Call to Server
    
    
    filename = log.get_filename()
    print('Successfully retrived' + filename)

def store_file_log(in_filepath,filesize, gen_count, mac, nonce, key, out_filepath=None):
    """ Stores information about file on the client-size.

        filesize:
            Size of the file.

        in_filepath:
            Name of the input file

        out_filepath:
            '<in_filepath>.clog' will always be used
            unless user specifies a name.

        gen_count:
            The version of this file. Starting value is 1.

        nonce:

        key: used to encrypt file
    """
    if not out_filepath:
        out_filepath = in_filepath + '.clog'

    log = ClientLog(out_filepath, nonce, key, gen_count)
    with open(out_filepath, 'wb') as outfile:
        pickle.dump(log, outfile, -1)
        
#Taken from http://stackoverflow.com/questions/8384737/python-extract-file-name-from-path-no-matter-what-the-os-path-format
def get_filename_from_filepath(filepath):
    """ Retrieve filename from the filepath
        regardless of os.
    """
    head, tail = ntpath.split(filepath)
    return tail or ntpath.basename(head)

def add_file_header(in_filepath, key):
    """ Adds a file header obj to the front of the file
        using Python's cpickle. 
        
        key: AES private key
    """
    out_filepath = in_filepath + '.fh'
    chunksize=64*1024
    nonce = generate_nonce(FILE_HEADER_NONCE_SIZE)
    mac = generate_mac(key, in_filepath)
    filename = get_filename_from_filepath(in_filepath)
    file_header = FileHeader(nonce, mac, filename)

    with open(in_filepath, 'rb') as infile:
        with open(out_filepath, 'wb') as outfile:

            pickle.dump(file_header, outfile, -1)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(chunk)
    outfile.close()

def read_file_header(in_filepath):
    """ Retrieves the file header object that is
        at the front of a file.
        Files read into this must have the
        extension '.fh'. Otherwise it will
        raise an error.
    """
    assert len(in_filepath) > 3
    assert in_filepath[-3:] == '.fh'
        
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
    assert len(in_filepath) > 3
    assert in_filepath[-3:] == '.fh'

    out_filepath = in_filepath[0:-3]
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
 
    
def has_file_header(in_filepath):
    """ Checks if this file has a file header
        placed by our encrypted file system
    """
    
    
#Taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def encrypt_file(in_filepath, out_filepath=None, chunksize=64*1024):
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
def decrypt_file(in_filepath, out_filepath=None, chunksize=64*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filepath, if not supplied
        will be in_filepath without its last extension
        (i.e. if in_filepath is 'aaa.zip.enc' then
        out_filepath will be 'aaa.zip')
    """

    if not out_filepath:
        out_filepath = os.path.splitext(in_filepath)[0]

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

