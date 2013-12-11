import cmd
import client
from client import Client

class Shell(cmd.Cmd):
    prompt = ">> "
    c = Client()


    def do_echo(self, line):
        self.c.echo(line)

    def do_mkdir(self, line):
        client.mkdir(line)

    def do_get(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: get src dst")
        client.get_file(p[0], p[1])

    def do_mv(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: mv source target")
        client.mv(p[0], p[1])

    def do_rm(self, line):
        pass

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

