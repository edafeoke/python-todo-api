#!/usr/bin/python3
""" objects that handle all default RestFul API actions for Users """
from click import password_option
from flask_restplus import Resource, fields, model
from models.user import User as Person
from models import storage
from api.v1.views import api
from flask import abort, jsonify, make_response, request
from api.v1.auth import Auth

@api.route('/users', strict_slashes=False)
class User(Resource):
    def get(self):
        """ returns list of all User objects """
        all_users = []
        users = storage.all(Person)
        if not users:
            abort(404)
        for user in users.values():
            print(user)
            d = user.to_dict()
            del d['_sa_instance_state']
            print(d)
            all_users.append(d)
        return jsonify(all_users)

    @api.expect(api.model('user', {
        'email': fields.String,
        'password': fields.String,
        'first_name': fields.String,
        'last_name': fields.String,
    }))
    def post(self):
        """ creates new user """

        data = request.get_json()
        if data is None:
            abort(400, "Not a JSON")
        if 'email' not in data:
            abort(400, "Missing email")
        if 'password' not in data:
            abort(400, "Missing password")
        user = Auth().register_user(data['email'], data['password'])

        for k, v in data.items():
            setattr(user, k, v)
        user.save()
        u = user.to_dict()
        del u['_sa_instance_state']
        print(u)
        return make_response(jsonify(u), 201)


@api.route('/users/<user_id>')
class UserID(Resource):
    def get(self, user_id):
        """ get a user by id """
        user = storage.get(Person, user_id)
        if user is None:
            abort(404)
        u = user.to_dict()
        del u['_sa_instance_state']
        return jsonify(u)

    def delete(self, user_id):
        """ handles DELETE method """
        user = storage.get(Person, user_id)
        if user is None:
            abort(404)
        user.delete()
        storage.save()
        return jsonify({}), 200

    def put(self, user_id):
        """ handles PUT method """
        user = storage.get(Person, user_id)
        if user is None:
            abort(404)
        data = request.get_json()
        if data is None:
            abort(400, "Not a JSON")
        for key, value in data.items():
            ignore_keys = ["id", "email", "created_at", "updated_at"]
            if key not in ignore_keys:
                print(key)
                setattr(user, key, value)
        user.save()
        u = user.to_dict()
        del u['_sa_instance_state']
        return make_response(jsonify(u), 200)
