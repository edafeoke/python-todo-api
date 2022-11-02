#!/usr/bin/python3

from email.policy import default
from models.base_model import BaseModel, Base
from os import getenv
# import sqlalchemy
from sqlalchemy import Boolean, Column, ForeignKey, String
from sqlalchemy.orm import relationship

HBNB_TYPE_STORAGE = getenv('HBNB_TYPE_STORAGE') or 'file'


class Todo(BaseModel, Base):
    '''Todo class'''

    __tablename__ = 'todos'

    if HBNB_TYPE_STORAGE == 'db':
        title = Column(String(256), nullable=False)
        user_id = Column(String(256),  ForeignKey('users.id'), nullable=False)
        isCompleted = Column(Boolean, default=False)


    def __init__(self, *args, **kwargs):
    #     """initializes user"""
        self.user_id = ''
        self.title = ''
        self.isCompleted = False
        super().__init__(*args, **kwargs)
