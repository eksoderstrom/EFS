import xmlrpc.client, random, struct, os, hashlib, sys, base64
from Crypto.Cipher import AES
#RSA imports
import Crypto.PublicKey.RSA as RSA
import Crypto.Random.OSRNG.posix as Nonce
#MAC import
import hmac
import ntpath
import pickle
#custom imports
from client_classes import FileHeader
from client_classes import FileLog
from client_classes import DirectoryLog

s = xmlrpc.client.ServerProxy('http://localhost:443')

#Macros
AES_KEY_SIZE = 32
RSA_KEY_SIZE = 2048
FILE_HEADER_NONCE_SIZE = 32

class Client():
    def __init__(self, uname, passwd):
        self.loggedin = False
        self.username = uname
        self.password = passwd

#########################################################
# Shell 
#
#########################################################
def set_proxy(proxy):
    global s 
    s = xmlrpc.client.ServerProxy(proxy)
    print("s set to " + proxy)

def login(uname, passwd):
    global c
    c = Client(uname, passwd)
    set_proxy('https://' + uname + ':' + passwd + '@localhost:443')
    try:
        s.echo("login")
    except xmlrpc.client.ProtocolError as err:
        print("invalid credentials, please login")
    print("successfully logged in as " + c.username)


def echo(arg):
    try:
        print(s.echo(arg))
    except xmlrpc.client.ProtocolError as err:
        print("invalid credentials")

def mkdir(path):
    s.mkdir(c.username, c.password, path)

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

def verify_mac(file_header, file_log, decrypted_file):
    """ Given a file header, we use the file
        log to verify that no one (who has not been
        given permission) has modified the file.
        We accomplish this by comparing the mac value
        in the file header against the new mac value
        we calculate from the contents of the decrypted
        file.

        Return true: file has not been tampered with
    """
    old_mac = file_header.get_mac()
    key = file_log.get_key()
    new_mac = generate_mac(key, decrypted_file)

    return old_mac == new_mac
def verify_generation_count(file_header, file_log):
    """ Given a file header, we use the file log to
        check if the file we obtained from the file
        server is at least as recent as when it was
        uploaded with this file log. This means that
        the generation count in the file header must
        be equal to or greater than the generation
        count in the file log.
    """
    new_gen_count = file_header.get_gen_count()
    old_gen_count = file_log.get_gen_count()

    return old_gen_count <= new_gen_count

########################################################
# These methods help with encrypting, decrypting, sending
# and retrieving files and directories
########################################################

def create_file(owner, filename, dst, s, db):
    """ This method creates a file on the server.
        
    """
    aes_key = generate_aes_key()
    rsa_key = generate_rsa_key(RSA_KEY_SIZE)
    new_filename = add_file_header(filename, aes_key, db, owner)
    encrypt_file(new_filename, aes_key)
    final_filename = new_filename + '.encrypted'
    
    #RPC Call here
    encrypted_name = generate_mac_for_filename(aes_key, get_filename_from_filepath(final_filename))
    dst = dst + '\' encrypted_name
    store_file_log(in_filepath, gen_count, aes_key, rsa_key, encrypted_name, owner)
    with open(final_filename, "rb") as handle:
        binary_data = xmlrpc.client.Binary(handle.read())
    s.receive_file(binary_data, dst)
    
def retrieve_from_server(log_filepath, s, db):
    """ This method retrieves a file from the server.
        ClientGUI should be able to call this directly.

        client_log: filepath to a client log
    """

    assert len(log_filepath) > 5
    assert log_filepath[-5:] == '.clog'

    with open(log_filepath, 'rb') as input:
        log = pickle.load(input)
    filename = log.get_encrypted_name()
    key = log.get_key()
    arg = s.send_file_to_client(filename)
    filename = log.get_filename()

    with open(filename, 'wb') as handle:
        handle.write(arg.data)
    decrypt_file(filename, key)
    assert len(filename) > 10
    remove_file_header(filename[0:-10])

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
        
def store_file_log(in_filepath, gen_count, aes_key, rsa_key, encrypted_name, owner):
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
            
        key: used to encrypt file

        encrypted_name: filepath on the encrypted file server
    """
    out_filepath = encrypted_name + '.clog'
    log = {}
    log['owner'] = owner
    
    log = FileLog(owner, in_filepath, aes_key, rsa_key, gen_count, encrypted_name)
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
    final_filename = out_filepath + '.encrypted'
    
    encrypted_name = generate_mac_for_filename(key, get_filename_from_filepath(final_filename))

    chunksize=64*1024
    mac = generate_mac(key, in_filepath)
    filename = get_filename_from_filepath(in_filepath)
    file_header = FileHeader(mac, gen_count)
    
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
    if get_filename_from_filepath(in_filepath) == 'test.txt.fh.encrypted':
        return True

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

