#!/usr/bin/python3
'''db_storage module'''
from os import getenv
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from models.base_model import Base, BaseModel
from models.user import User
from models.todo import Todo
import models

classes = {User: "User", Todo: "Todo"}


class DBStorage:
    '''DBStorage class'''

    __engine = None
    __session = None

    def __init__(self) -> None:
        HBNB_MYSQL_USER = getenv('HBNB_MYSQL_USER')
        HBNB_MYSQL_PWD = getenv('HBNB_MYSQL_PWD')
        HBNB_MYSQL_HOST = getenv('HBNB_MYSQL_HOST')
        HBNB_MYSQL_DB = getenv('HBNB_MYSQL_DB')
        HBNB_ENV = getenv('HBNB_ENV')

        self.__engine = create_engine(
            f'mysql+mysqldb://{HBNB_MYSQL_USER}:{HBNB_MYSQL_PWD}@{HBNB_MYSQL_HOST}/{HBNB_MYSQL_DB}', echo=True, pool_pre_ping=True)
        if HBNB_ENV == "test":
            Base.metadata.drop_all(self.__engine)

    def all(self, cls=None):
        '''query on the current database session'''
        new_dict = {}

        if not cls:
            for c in classes.keys():
                objs = self.__session.query(c).all()
                for obj in objs:
                    key = obj.__class__.__name__ + '.' + obj.id
                    new_dict[key] = obj
            return new_dict

        if cls in classes.keys():
            objs = self.__session.query(cls).all()
            for obj in objs:
                key = obj.__class__.__name__ + '.' + obj.id
                new_dict[key] = obj
            return new_dict

        # for clss in classes:
        #     if cls is None or cls is classes[clss] or cls is clss:
        #         objs = self.__session.query(classes[clss]).all()
        #         for obj in objs:
        #             key = obj.__class__.__name__ + '.' + obj.id
        #             new_dict[key] = obj
        # return (new_dict)

    def new(self, obj):
        """add the object to the current database session"""
        self.__session.add(obj)

    def save(self):
        """commit all changes of the current database session"""
        self.__session.commit()

    def delete(self, obj=None):
        """delete from the current database session obj if not None"""
        if obj is not None:
            self.__session.delete(obj)

    def reload(self):
        """reloads data from the database"""
        Base.metadata.create_all(self.__engine)
        sess_factory = sessionmaker(bind=self.__engine, expire_on_commit=False)
        Session = scoped_session(sess_factory)
        self.__session = Session

    def close(self):
        """call remove() method on the private session attribute"""
        self.__session.remove()

    def get_session(self):
        return self.__session

    def get(self, cls, id):
        '''Returns the object based on the class and its ID, or None if not found'''

        if cls not in classes:
            return None
        all_objs = self.all(cls)

        if cls and id:
            if f'{cls.__name__}.{id}' in all_objs.keys():
                return all_objs[f'{cls.__name__}.{id}']
            return None
        else:
            return None

    def count(self, cls=None):
        """
        count the number of objects in storage
        """
        if cls == None:
            return len(self.all().keys())
        else:
            c = 0
            for obj in self.all().values():
                if obj.__class__.__name__ == cls:
                    c += 1
            return c
