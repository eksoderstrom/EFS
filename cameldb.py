from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, ForeignKey, Sequence
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship


Base = declarative_base()



read_permissions = Table(
    "read_permissions",
    Base.metadata,
    Column("fk_file", String(128), ForeignKey("files.path")),
    Column("fk_user", String(128), ForeignKey("users.username")),
)

write_permissions = Table(
    "write_permissions",
    Base.metadata,
    Column("fk_file", String(128), ForeignKey("files.path")),
    Column("fk_user", String(128), ForeignKey("users.username")),
)


class User(Base):
    __tablename__ = "users"

    username = Column(String(128), primary_key=True)
    password = Column(String(128))
    token = Column(String(128))
    salt = Column(String(128))


class File(Base):
    __tablename__ = "files"

    path = Column(String(128), primary_key=True)
    owner = Column(String(128))
    perm = Column(String(50))

    read_permissions = relationship(
        "User",
        backref="files",
        secondary=read_permissions
    )

    write_permissions = relationship(
        "User",
        secondary=write_permissions
    )


def db_setup():
    engine = create_engine("sqlite:///perm.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)
    return session()
    


import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: [init-db]" % sys.argv[0])
        exit(1)
    cmd = sys.argv[1]
    if cmd == 'init-db':
        db_setup()
    else:
        raise Exception("unknown command %s" % cmd)
