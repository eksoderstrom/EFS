import cmd, os
import client
from client import Client

class Shell(cmd.Cmd):
    prompt = ">> "
    c = Client()


    #share read access with recipient
    def do_sr(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: sr path recipient")
        else:
            self.c.share_read(p[0], p[1])

    # share write access with recipient
    def do_sw(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: sw path recipient")
        else:
            self.c.share_write(p[0], p[1])

    def do_decrypt(self, line):
        p = line.split()
        if len(p) != 1:
            print("Usage: decrypt filename")
        elif os.path.isfile(p[0]):
            client.decrypt(self.c.username, p[0])
        else:
            print("filename not found")
        

    def do_echo(self, line):
        self.c.echo(line)

    def do_mkdir(self, line):
        p = line.split()
        if len(p) != 1:
            print("Usage: mkdir dirname")
        else:
            self.c.mkdir(line)

    def do_get(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: get src dst")
        elif os.path.isdir(p[1]):
            self.c.get_file(p[0], p[1])
        else:
            print("dst must be a directory")

    def do_mv(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: mv source target")
        client.mv(p[0], p[1])

    def do_rm(self, line):
        p = line.split()
        if len(p) != 1:
            print("Usage: rm target")
        self.c.rm(p[0])

    def do_enc(self, line):
        p = line.split()
        client.enc(p[0])

    def do_dec(self, line):
        p = line.split()
        client.dec(p[0])

    def do_login(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: login username password")
        else:
            self.c.login(p[0], p[1])

    def do_logout(self, line):
        p = line.split()
        if len(p) != 0:
            print("Usage: logout")
        else:
            self.c.logout()

    def do_ls(self, line):
        p = line.split()
        if len(p) == 1:
            self.c.ls(p[0])
        elif len(p) == 0:
            self.c.ls()
        else:
            print("Usage: ls path")
    
    def do_pwd(self, line):
        p = line.split()
        if len(p) != 0:
            print("Usage: pwd")
        else:
            self.c.pwd()

    def do_cd(self, line):
        p = line.split()
        if len(p) != 1:
            print("Usage: cd directory")
        else:
            self.c.cd(p[0])

    def do_register(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: register username password")
        else:
            self.c.register(p[0], p[1])

    def do_whoami(self, line):
        p = line.split()
        if len(p) != 0:
            print("Usage: whoami")
        else:
            self.c.whoami()
    

    def do_EOF(self, line):
        return True

    def do_create(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: create souce dst")
        else:
            self.c.create(p[0], p[1])            

    """
    The following methods should be available for testing only, and should be removed for the final product.
    """
    def do_xfer(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: xfer source dst")
        else:
            self.c.xfer(p[0], p[1])

if __name__ == '__main__':
    Shell().cmdloop("Encrypted File System commandline interface. Use 'help' to get a listing of available shell commands")

