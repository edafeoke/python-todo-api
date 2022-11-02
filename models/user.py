#!/usr/bin/python3

from models.base_model import BaseModel, Base
from os import getenv
import sqlalchemy
from sqlalchemy import Column, String
from sqlalchemy.orm import relationship

HBNB_TYPE_STORAGE = getenv('HBNB_TYPE_STORAGE') or 'file'


class User(BaseModel, Base):
    '''User class'''

    __tablename__ = 'users'

    if HBNB_TYPE_STORAGE == 'db':
        email = Column(String(128), nullable=False)
        password = Column(String(128), nullable=False)
        first_name = Column(String(128), nullable=True)
        last_name = Column(String(128), nullable=True)
        session_id = Column(String(128), nullable=True)
        reset_token = Column(String(128), nullable=True)
        
        todos = relationship('Todo', backref='user', cascade='delete')

    def __init__(self, *args, **kwargs):
    #     """initializes user"""
        self.email = ''
        self.password = ''
        self.first_name = ''
        self.last_name = ''
        self.session_id = ''
        self.reset_token = ''
        super().__init__(*args, **kwargs)
