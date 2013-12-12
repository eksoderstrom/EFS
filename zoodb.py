from sqlalchemy import *
from sqlalchemy.orm import *
from sqlalchemy.ext.declarative import *
import os

PersonBase = declarative_base()

class Person(PersonBase):
    __tablename__ = "person"
    username = Column(String(128), primary_key=True)
    password = Column(String(128))
    token = Column(String(128))
    #zoobars = Column(Integer, nullable=False, default=10)
    #profile = Column(String(5000), nullable=False, default="")
    salt = Column(String(128))


def dbsetup(name, base):
    thisdir = os.path.dirname(os.path.abspath(__file__))
    dbdir   = os.path.join(thisdir, "db", name)
    if not os.path.exists(dbdir):
        os.makedirs(dbdir)

    dbfile  = os.path.join(dbdir, "%s.db" % name)
    engine  = create_engine('sqlite:///%s' % dbfile)
    base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)
    return session()

def person_setup():
    return dbsetup("person", PersonBase)


import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s [init-person]" % sys.argv[0])
        exit(1)

    cmd = sys.argv[1]
    if cmd == 'init-person':
        person_setup()
    else:
        raise Exception("unknown command %s" % cmd)
