import xmlrpc.client, random, struct, os, hashlib, sys, base64
from Crypto.Cipher import AES
#RSA imports
import Crypto.PublicKey.RSA as RSA
import Crypto.Random.OSRNG.posix as Nonce
#MAC import
import hmac

"""TODO
    how to associate private keys with files
    """

s = xmlrpc.client.ServerProxy('http://localhost:8000')
key = '0123456789abcdef'    #Key should of course not be hard-coded, and should be stored on disk. placeholder for now

#Macros
AES_KEY_SIZE = 256
RSA_KEY_SIZE = 1024
FILE_HEADER_NONCE_SIZE = 32
WARNING = 'DO NOT DELETE THIS FILE. USED IN ENCRYPTED FILE SYSTEM.'

class Client():
    def __init__(self, username, password):
        pass

#########################################################
# 
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

def generate_mac(key, filename):
    """ Generates a mac
        key: AES key
        filename: name of file to hmac
    """
    mac = hmac.new(key, None, hashlib.sha256)

    filesize = os.path.getsize(filename) 

    with open(filename, 'rb') as infile:
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            mac.update(chunk)
    return mac.hexdigest()

def export_rsa_key_pair(filename, key, passphrase=None):
    """ Save a copy of our rsa key pair
        Treat this as saving the private
        key. Do not distribute this file.
    """
    try:
        f = open(filename, 'w')
        f.write(key.exportKey())
        f.close()
    except IOError as e:
        print(e)

def export_rsa_public_key(filename, key):
    """ Saves a copy of the public key
        only.

        filename:
        key: RSA key object
    """
    filename = filename + '.pub'
    try:
        f = open(filename, 'w')
        f.write(key.publickey().exportKey())
        f.close()
    except IOError as e:
        print(e)
        
def load_rsa_key(filename, passphrase=None):
    """ Retrieve our rsa key from file

        filename: name of file containing
        public-private key pair
    """
    try:
        f = open(filename)
        key = RSA.importKey(f.read())
        f.close()
        return key
    except IOError as e:
        print (e)

def save_key_pair(filename, rsa_key):
    """ Saves the user's public-private
        key pair for later retrieval.

        filename: name of file where
        keys will be stored. Two files
        will be made with extensions
        '.pub' and '.pri' for public
        and private keys, respectively.

        rsa_key: RSA key object
    """
    export_rsa_key_pair(filename)
    export_rsa_public_key(filename)
    

def send_public_key(key):
    key.publickey().exportKey()


def xfer(source):
    with open(source, "rb") as handle:
        binary_data = xmlrpc.client.Binary(handle.read())
    s.receive_file(binary_data)

def mv(source, dst):
    pass

def enc(fn):
    new_in_filename = add_file_header(fn)
    encrypt_file(new_in_filename)

def dec(fn):
    decrypt_file(fn, "/Users/eks/Desktop/decrypted")

def store_file_log(in_filename, filesize, gen_count, mac):
    """ Stores information about file on the client-size.

        filesize:
            Size of the file.

        in_filename:
            Name of the input file

        out_filename:
            '<in_filename>.txt' will always be used.

        gen_count:
            The version of this file. Starting value is 1.
    """
    out_filename = in_filename + '.txt'
    nonce = os.urandom(32)
    with open(out_filename, 'wb') as outfile:
        outfile.write(in_filename)
        outfile.write(filesize)
        outfile.write(gen_count)
        outfile.write(mac)

def add_file_header(in_filename, key):
    """ Adds a file header to the front of the file of the format
        FILEHEADER_START
        FILEHEADER_END

        key: aes private key
    """

    start = 'FILEHEADER_START'
    end = 'FILEHEADER_END'
    nonce = generate_nonce(FILE_HEADER_NONCE_SIZE)

def has_file_header(in_filename):
    """ Checks if this file has a file header
        placed by our encrypted file system
    """
    
    
#Taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def encrypt_file(in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
        

    if not out_filename:
        out_filename = in_filename + '.encrypted'

    iv = bytes([ random.randint(0, 0xFF) for i in range(16)])
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename) 

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
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
def decrypt_file(in_filename, out_filename=None, chunksize=64*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """

    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

