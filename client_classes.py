from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import pickle, os
import Crypto.Random as Random
import Crypto.Random.random as random
from Crypto.Cipher import AES
##########################################################################
# File Header 
# This class is used to keep track of certain parameters and is inserted
# at the front of the file we want to encrypt.
##########################################################################
class FileHeader():
    def __init__(self, filename, signature, gen_count):
        """ The parameters stored in the file header
            are used for security and identification
            purposes.
            nonce: random number in bytes
            mac: used to verify the file
            filename: plaintext filename
        """
        self.filename = filename
        self.signature = signature
        self.gen_count = gen_count

    def get_filename(self):
        return self.filename

    def get_gen_count(self):
        return self.gen_count

    def get_signature(self):
        return self.signature

#############################################################################
# AccessBlock
# This class encapsulates permissions for a user.
# user_rsa_key: Used for encrypting permission blocks per user 
# file_aes_key: Used for encrypting data file contents 
# file_dsa_key: Used for signing data file contents.
# Presence only of file_aes_key points to read-only permission.
# If file_dsa_key is also included, user has read-write
# permission.
#############################################################################

class AccessBlock():

    def __init__(self, file_aes_key, file_dsa_key=None):
        self.file_aes_key = file_aes_key
        self.file_dsa_key = file_dsa_key
        self.helper_aes = None
    def get_file_encryption_key(self):
        return self.file_aes_key

    def get_file_signature_key(self):
        return self.file_dsa_key

    def set_file_signature_key(self, file_dsa_key):
        self.file_dsa_key = file_dsa_key

    def encrypt_permission_block(self, user_encryption_cipher):
        self.file_aes_key = user_encryption_cipher.encrypt(self.file_aes_key)
        
        if self.file_dsa_key:
            aes_key = os.urandom(32)
            self.helper_aes = user_encryption_cipher.encrypt(aes_key)
            self.file_dsa_key = self.dump_key(aes_key, self.file_dsa_key, user_encryption_cipher)

    def dump_key(self, aes_key, file_dsa_key, cipher):
        dumpedkey = pickle.dumps(file_dsa_key)
        iv = bytes([ random.randint(0, 0xFF) for i in range(16)])
        encryptor = AES.new(aes_key, AES.MODE_CFB, iv)
        cipher = iv + encryptor.encrypt(dumpedkey)
        return cipher

    def load_key(self, aes_key, enc_key, cipher_key):
        iv = enc_key[:16]
        decrypt = AES.new(aes_key, AES.MODE_CFB, iv)
        plaintext = decrypt.decrypt(enc_key[16:])
        return pickle.loads(plaintext)

    def decrypt_permission_block(self, user_encryption_cipher):
        self.file_aes_key = user_encryption_cipher.decrypt(self.file_aes_key)
        if self.file_dsa_key:
            self.helper_aes = user_encryption_cipher.decrypt(self.helper_aes)
            self.file_dsa_key = self.load_key(self.helper_aes, self.file_dsa_key, user_encryption_cipher)

