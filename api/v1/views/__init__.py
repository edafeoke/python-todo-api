#!/usr/bin/python3
""" Blueprint for API """
from flask import Blueprint
from flask_restplus import Api
from api.v1.auth import authorization

app_views = Blueprint('app_views', __name__, url_prefix='/api/v1')


api = Api(app_views,
          authorizations=authorization,
          title="CodeBase API docs",
          version='1.3')

from api.v1.views.index import *
from api.v1.views.users import *
from api.v1.views.todos import *

# from api.v1.views.places import *
# from api.v1.views.places_reviews import *
# from api.v1.views.cities import *