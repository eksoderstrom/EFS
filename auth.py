import os
from cameldb import *

import hashlib
import random
import binascii
import pbkdf2

def authenticate(username, password):
    db = db_setup()
    user = db.query(User).get(username)
    if user:
        return user.password == str(pbkdf2.PBKDF2(password, user.salt).hexread(32))
    return False
    

def login(username, password):
    db = db_setup()
    user = db.query(User).get(username)
    if not user:
        return None
    if user.password == str(pbkdf2.PBKDF2(password, user.salt).hexread(32)):
        return True
    else:
        return None

def register(username, password):
    db = db_setup()
    user = db.query(User).get(username)
    salt = str(binascii.hexlify(os.urandom(16)))
    if user:
        return None
    newperson = User()
    newperson.salt = salt
    newperson.username = username
    newperson.password = str((pbkdf2.PBKDF2(password, salt)).hexread(32))
    db.add(newperson)
    db.commit()
    return True

def add_file(path, owner):
    db = db_setup()
    abspath = os.path.abspath(path)
    user = db.query(User).get(owner)
    fil = db.query(File).get(abspath)
    print('add file')
    if user:
        newfile = File()
        newfile.path = abspath
        newfile.owner = owner
        newfile.read_permissions.append(user)
        db.add(newfile)
        db.commit()

def add_read(username, path):
    db = db_setup()
    abspath = os.path.abspath(path)
    user = db.query(User).get(username)
    fil = db.query(File).get(abspath)
    if user and fil:
        fil.read_permissions.append(user)
        db.commit()
        return True
    else:
        return False

def isOwner(username, path):
    abspath = os.path.abspath(path)
    db = db_setup()
    fil = db.query(File).get(abspath)
    if fil:
        return fil.owner == username
    return False
    

def has_read(username, path):
    db = db_setup()
    abspath = os.path.abspath(path)
    user = db.query(User).get(username)
    fil = db.query(File).get(abspath)
    if user and fil:
        if fil.owner == username:
            return True
        if user in fil.write_permissions:
            return True
        return user in fil.read_permissions
    return False
