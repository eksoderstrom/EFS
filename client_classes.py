##########################################################################
# Directory Log
# This class is use to store data about a directory on the client. It
# is added to the front of a .clog file. After that, the file logs are then
# written to the file
#########################################################################
class DirectoryLog():
    def __init__(self, files=[]):
        """ Keeps track of the number of files in the
        directory.
        """
        self.files = files

    def get_files(self):
        return self.files


##########################################################################
# Client Log
# This class is used to store data abaout individual files on the client.
# The main reason why client log objects are used as opposed to simply
# writing the parameters of a file to the .clog file is because it is easier
# to extract information, especially if we choose to store more than one file
# in an client log file (ie: store a directory of files in a single client
# file)
##########################################################################
class FileLog():
    def __init__(self, owner, filename, aes_key, rsa_key, gen_count, encrypted_name):
        """ The parameters used here are for
            retrieval and identification
            purposes.
            
            filename:
        """
        self.aes_key = aes_key
        self.filename = filename
        self.gen_count = gen_count
        self.encrypted_name = encrypted_name
        self.owner = owner
        self.rsa_key = rsa_key
        self.shared_users = {}

    def get_owner(self):
        return self.owner

    def get_aes_key(self):
        return self.aes_key

    def get_rsa_key(self):
        return self.rsa_key

    def get_gen_count(self):
        return self.gen_count

    def get_filename(self):
        return self.filename

    def get_encrypted_name(self):
        return self.encrypted_name

##########################################################################
# File Header 
# This class is used to keep track of certain parameters and is inserted
# at the front of the file we want to encrypt.
##########################################################################
class FileHeader():
    def __init__(self, signature, gen_count):
        """ The parameters stored in the file header
            are used for security and identification
            purposes.

            nonce: random number in bytes
            mac: used to verify the file
            filename:
        """
        self.signature
        self.gen_count

    def get_gen_count(self):
        return self.gen_count

    def get_signature(self):
        return self.signature

#############################################################################
# AccessBlock
# This class encapsulates permissions for a user.
# Presence only of File Encryption Key points to read-only permission.
# If File Signature Key (private half) is also included, user has read-write
# permission.
#############################################################################

class AccessBlock():
    
    def __init__(self, username, fek, fsk=None):
        self.username = username
        self.fek = fek
        self.fsk = fsk

    def get_username(self):
        return self.username

    def get_file_encryption_key(self):
        return self.fek

    def get_file_signature_key(self):
        return self.fsk