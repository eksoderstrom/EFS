from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

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
            filename:
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

    def get_file_encryption_key(self):
        return self.file_aes_key

    def get_file_signature_key(self):
        return self.file_dsa_key

    def set_file_signature_key(self, file_dsa_key):
        self.file_dsa_key = file_dsa_key

    def encrypt_permission_block(self, mek_cipher):
        self.file_aes_key = mek_cipher.encrypt(self.file_aes_key)
        if not self.file_dsa_key:
            self.file_dsa_key = mek_cipher.encrypt(self.file_dsa_key)

    def decrypt_permission_block(self, mek_cipher):
        self.file_aes_key = mek_cipher.decrypt(self.file_aes_key)
        if not self.file_dsa_key:
            self.file_dsa_key = mek_cipher.decrypt(self.file_dsa_key)

