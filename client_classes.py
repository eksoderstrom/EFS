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
# user_rsa_key: Used for encrypting permission blocks per user 
# file_aes_key: Used for encrypting data file contents 
# file_dsa_key: Used for signing data file contents.
# Presence only of file_aes_key points to read-only permission.
# If file_dsa_key is also included, user has read-write
# permission.
#############################################################################

class AccessBlock():
    
    def __init__(self, username, user_rsa_key, file_aes_key, file_dsa_key=None):
        self.username = username
        self.user_rsa_key = user_rsa_key
        self.encrypted_file_aes_key = file_aes_key #not encrypted yet in initialization
        self.encrypted_file_dsa_key = file_dsa_key #not encrypted yet in initialization  
        self.safeToGet = False #not yet safe to ask for keys, because they haven't been encrypted

    def get_username(self):
        return self.username

    def encrypt_permission_block(self):

        #ToDo: Encrypt file_aes_key and file_dsa_key (this may be None) with user_rsa_key 
        #      set encrypted_file_aes_key and self_encrypted_file_dsa_key 
        #      when encryption done, set self.safeToGet = True


    def decrypt_permission_block(self):
        #TODO: Decrypt file_aes_key and file_dsa_key (this may be None) using user_rsa_key.

    def get_encrypted_file_aes_key(self):
        if self.safeToGet:
            return self.encrypted_file_aes_key

    def get_encrypted_file_dsa_key(self):
        if self.safeToGet:
            return self.encrypted_file_dsa_key


