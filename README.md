EFS
===

The overall goal of the encrypted filesystem (EFS) is to provide dropbox-like behavior in which a malicious fileserver is unable to read user data or even modify user data without being detected. This repository provides a python shell prototype for encrypted filesystem. Each user generates an RSA public/private key pair and a DSA public/private key pair. The client encrypts files with an AES symmetric key. Write permission is given by encrypting the AES key using the target user's RSA key. The encrypted key is appended to the file metadata. Write permission is granted by appending the encrypted file signing key to the file metadata.
