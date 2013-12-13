import os
import auth
import socket
import socketserver
import ssl
import pickle
import xmlrpc.client
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCDispatcher, SimpleXMLRPCRequestHandler
try:
    import fcntl
except ImportError:
    fcntl = None

KEYFILE='privatekey.pem'    # Replace with your PEM formatted key file
CERTFILE='cert.pem'  # Replace with your PEM formatted certificate file
ROOTDIR='/Users/eks/EFS/server/'
INSUFFICIENT_PRIVILEGE_EXCEPTION = -2


class SimpleXMLRPCServerTLS(SimpleXMLRPCServer):
    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
                 logRequests=True, allow_none=False, encoding=None, bind_and_activate=True):
        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)

        class VerifyingRequestHandler(SimpleXMLRPCRequestHandler):
            # this is the method we must override
            def parse_request(self):
                # first, call the original implementation which returns
                # True if all OK so far
                if SimpleXMLRPCRequestHandler.parse_request(self):
                    return True
                return False
        
        #    Override the normal socket methods with an SSL socket
        socketserver.BaseServer.__init__(self, addr, VerifyingRequestHandler)
        self.socket = ssl.wrap_socket(
            socket.socket(self.address_family, self.socket_type),
            server_side=True,
            keyfile=KEYFILE,
            certfile=CERTFILE,
            cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_SSLv23,
            )
        if bind_and_activate:
            self.server_bind()
            self.server_activate()


        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

def executeRpcServer():
    # Create server
    server = SimpleXMLRPCServerTLS(("localhost", 443), requestHandler=RequestHandler)
    server.register_introspection_functions()

    # Register an instance; all the methods of the instance are
    # published as XML-RPC methods (in this case, just 'div').
    class MyFuncs:
        def login(self, username, password):
            if auth.login(username, password):
                return 'ok'
            else:
                return 'fail'

        def echo(self, arg):
            return arg

        def ls(self, username, password, path):
            if auth.authenticate(username, password):
                return os.listdir(ROOTDIR + path)
            return False


        def receive_file(self, username, password, arg, dst):
            if auth.authenticate(username, password):
                if os.path.isfile(ROOTDIR + dst):
                    if auth.has_write(username, ROOTDIR + dst):
                        with open(ROOTDIR + dst, "wb") as handle:
                            handle.write(arg.data)
                            return True
                    else:
                        return INSUFFICIENT_PRIVILEGE_EXCEPTION
                else:
                    print('righthere')
                    with open(ROOTDIR + dst, "wb") as handle:
                        handle.write(arg.data)
                        auth.add_file(ROOTDIR + dst, username)
                        return True

        def send_file_to_client(self, username, password, path):
            if auth.authenticate(username, password):
                if auth.has_read(username, ROOTDIR + '/' + path):
                    with open(ROOTDIR + path, "rb") as handle:
                        return xmlrpc.client.Binary(handle.read())
                else:
                    return False

        def rm(self, username, password, filename):
            if auth.authenticate(username, password):
                print('authenticated')
                path = os.path.abspath(ROOTDIR + '/' + filename)
                if auth.isOwner(username, path):
                    os.remove(path)
                    return True
            return False


        def share_read(self, username, password, path, recipient):
            if auth.authenticate(username, password):
                if auth.isOwner(username, ROOTDIR + '/' + path):
                    auth.add_read(recipient, path)
                    return True
                return False
                

        def register(self, username, password):
            if auth.register(username, password):
                try:
                    os.makedirs(os.path.abspath(ROOTDIR + "/" + username+ "/"))
                    auth.add_file(os.path.abspath(ROOTDIR + '/' + username + '/'), username)
                except OSError as exc:
                    return False
                return 'ok'
            else:
                return 'fail'

        """
        private methods not exposed through the shell
        """


        """
        unimplemented functions
        """

        def mkdir(self, username, password, path):
            try:
                os.makedirs(ROOTDIR + "/" + username+ "/" + path)
                return True
            except OSError as exc:
                return False
 
        
        #    For this test pickle function I am assuming the pickled object is just a list
        def uploadPickle(self, pickleStringBinary):
            #    Get the binary data from the pickled string
            pickleData = pickleStringBinary.data
            #    Unpickle the data into an object
            pickObject = pickle.loads(pickleData)
            #    Print the object to test
            print (pickObject[-1])
            #    Modify the object to test
            pickObject.append("Server got pickled object")
            #    Pickle the object. Protocol=2 is required to support Python v2 clients
            newPickleString = pickle.dumps(pickObject, protocol=2)
            #    Label the string binary and send it back to the XML client 
            return xmlrpc.client.Binary(newPickleString)

    server.register_instance(MyFuncs())

    # Run the server's main loop
    print("Starting XML RPC Server")
    server.serve_forever()


if __name__ == '__main__':   
    executeRpcServer()
