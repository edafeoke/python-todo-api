#!/usr/bin/python3
""" Blueprint for API """
from flask import Blueprint
from flask_restx import Api
from api.v1.auth import authorization
from dotenv import dotenv_values

app_views = Blueprint('app_views', __name__, url_prefix='/api/v1')



env = dotenv_values(".env")
app_name = ''

if 'APP_NAME' in env.keys():
    app_name = env['APP_NAME']

api = Api(app_views,
          authorizations=authorization,
          title=f"{app_name} API docs",
          version='1.3')

from api.v1.views.index import *
from api.v1.views.users import *
from api.v1.views.todos import *

# from api.v1.views.places import *
# from api.v1.views.places_reviews import *
# from api.v1.views.cities import *