import logging
import os
from contextlib import contextmanager
from typing import List

from sqlalchemy import String, Column, create_engine, Integer
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from const import ROOT

_ORM_BASE = declarative_base()


class User(_ORM_BASE):
    __tablename__ = 'USER'
    email = Column(String(50), primary_key=True)
    pwd = Column(String(40))
    subscribe = Column(Integer, default=0)


class Sender(_ORM_BASE):
    __tablename__ = 'SENDER'
    email = Column(String(50), primary_key=True)
    pwd = Column(String(20))
    smtp_server = Column(String(50))
    smtp_port = Column(Integer, default=465)


_DB_PATH = os.path.join(ROOT, 'E-mail Subscriptions System.sqlite3')
_ENGINE = create_engine(f'sqlite:///{_DB_PATH}')
_SESSION_CLZ = sessionmaker(bind=_ENGINE)

# create table if not exist
User.__table__.create(bind=_ENGINE, checkfirst=True)
Sender.__table__.create(bind=_ENGINE, checkfirst=True)


@contextmanager
def session() -> Session:
    try:
        s = _SESSION_CLZ()
        yield s
        s.commit()
    except Exception as e:
        logging.exception(e)
        raise


def all_subscriber() -> List[str]:
    with session() as s:
        ret: List[User] = s.query(User).filter(User.subscribe > 0).all()
        return [e.email for e in ret]


if __name__ == '__main__':
    print(all_subscriber())
