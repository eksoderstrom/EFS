import cmd
import client

class Shell(cmd.Cmd):
    prompt = ">> "

    def do_xfer(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: xfer source dst")
        client.xfer(p[0], p[1])

    def do_echo(self, line):
        client.echo(line)

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
        client.login(p[0], p[1])

    def do_ls(self, line):
        p = line.split()
        if len(p) == 1:
            client.ls(p[0])
        elif len(p) == 0:
            client.ls()
        else:
            print("Usage: ls path")
    
    def do_pwd(self, line):
        p = line.split()
        if len(p) != 0:
            print("Usage: pwd")
        else:
            client.pwd()

    def do_cd(self, line):
        p = line.split()
        if len(p) != 1:
            print("Usage: cd directory")
        else:
            client.cd(p[0])

    def do_register(self, line):
        p = line.split()
        if len(p) != 2:
            print("Usage: register username password")
        else:
            client.register(p[0], p[1])

    def do_EOF(self, line):
        return True

if __name__ == '__main__':
    Shell().cmdloop("Encrypted File System commandline interface. Use 'help' to get a listing of available shell commands")

