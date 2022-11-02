#!/usr/bin/python3
'''base_model module'''

from uuid import uuid4
from datetime import datetime
import models
from sqlalchemy import Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()

class BaseModel:
    """base model class"""

    id = Column(String(60), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    def __init__(self, *args, **kwargs):
        if kwargs:
            for k, v in kwargs.items():
                if k != '__class__':
                    val = None
                    if k == 'updated_at' or k == 'created_at':
                        val = datetime.fromisoformat(v)
                        setattr(self, k, val)
                    else:
                        setattr(self, k, v)

        else:
            self.id = str(uuid4())
            self.created_at = datetime.utcnow()
            self.updated_at = datetime.utcnow()

    def __str__(self):
        return f"[{self.__class__.__name__}] ({self.id}) {self.__dict__}"

    def save(self):
        self.updated_at = datetime.utcnow()
        models.storage.new(self)
        models.storage.save()

    def to_dict(self):
        obj = self.__dict__.copy()
        obj['__class__'] = self.__class__.__name__
        obj['updated_at'] = obj['updated_at'].isoformat()
        obj['created_at'] = obj['created_at'].isoformat()
        return obj

    def delete(self):
        '''
        delete the current instance from the storage
        '''
        models.storage.delete(self)
