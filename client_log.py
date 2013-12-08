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
    def __init__(self, filename, nonce, key, gen_count, encrypted_name):
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
