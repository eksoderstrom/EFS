##########################################################################
# Directory Log
# This class is use to store data about a directory on the client. It
# is added to the front of a .clog file. After that, the file logs are then
# written to the file
#########################################################################
class DirectoryLog():
    def __init__(self, num_files):
        """ Keeps track of the number of files in the
        directory.
        """
        self.num_files = num_files

    def get_num_files(self):
        return self.num_files

    def inc_num_files(self):
        self.num_files = self.num_files + 1

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
    def __init__(self, filename, nonce, key, gen_count, mac, encrypted_name):
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
        self.encrypted_name = encrypted_name
        self.mac = mac

    def get_nonce(self):
        return self.nonce

    def get_key(self):
        return self.key

    def get_gen_count(self):
        return self.gen_count

    def get_filename(self):
        return self.filename

    def get_encrypted_name(self):
        return self.encrypted_name

    def get_mac(self):
        return self.mac

##########################################################################
# File Header 
# This class is used to keep track of certain parameters and is inserted
# at the front of the file we want to encrypt.
##########################################################################
class FileHeader():
    def __init__(self, nonce, mac, filename, gen_count):
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
        self.gen_count = gen_count

    def get_nonce(self):
        return self.nonce

    def get_mac(self):
        return self.mac

    def get_filename(self):
        return self.filename

    def get_gen_count(self):
        return self.gen_count
