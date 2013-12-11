import os
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

userPassDict = {"eric":"e",
                "tiffany":"t"}

permissionsDict = {}
    
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
                    print("parsing")
                    # next we authenticate
                    return True
                    """
                    if self.authenticate(self.headers):
                        return True
                    else:
                    """
                        # if authentication fails, tell the client
                    self.send_error(401, 'Authentication failed')
                return False
            
            def authenticate(self, headers):
                from base64 import b64decode
                #    Confirm that Authorization header is set to Basic
                (basic, _, encoded) = headers.get('Authorization').partition(' ')
                assert basic == 'Basic', 'Only basic authentication supported'
                
                #    Encoded portion of the header is a string
                #    Need to convert to bytestring
                encodedByteString = encoded.encode()
                #    Decode Base64 byte String to a decoded Byte String
                decodedBytes = b64decode(encodedByteString)
                #    Convert from byte string to a regular String
                decodedString = decodedBytes.decode()
                #    Get the username and password from the string
                (username, _, password) = decodedString.partition(':')
                #    Check that username and password match internal global dictionary
                if username in userPassDict:
                    if userPassDict[username] == password:
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
        """
        functions related to authentication and registration
        """
        def login(self, username, password):
            if userPassDict[username] == password:
                return "ok"
            else:
                return "fail"

        """
        functions related to filesystem navigation
        """
        def echo(self, arg):
            return arg

        def ls(self, username, password, path):
            return os.listdir(ROOTDIR + path)

        def mkdir(self, username, password, path):
            try:
                os.makedirs(ROOTDIR + "/" + username+ "/" + path)
                return True
            except OSError as exc:
                return False
 

        def receive_file(self, arg, dst):
            with open(dst, "wb") as handle:
                handle.write(arg.data)
                return True

        def send_file_to_client(self, path):
            with open(path, "rb") as handle:
                return xmlrpc.client.Binary(handle.read())

        def register(self, username, password):
            if username in userPassDict:
                return "fail"
            else:
                userPassDict[username] = password
                return "ok"



        def rm(self, path):
            pass

        
        
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
