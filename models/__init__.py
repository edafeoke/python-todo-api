#!/usr/bin/python3
'''Initailization file'''

from os import getenv

HBNB_TYPE_STORAGE = getenv('HBNB_TYPE_STORAGE')

storage = None

if HBNB_TYPE_STORAGE == 'db':
    from models.engine.db_storage import DBStorage
    storage = DBStorage()
else:
    from models.engine.file_storage import FileStorage
    storage = FileStorage()

storage.reload()