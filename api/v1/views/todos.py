#!/usr/bin/python3
""" objects that handle all default RestFul API actions for Todos """

# import api
from models.todo import Todo
from models.user import User
from models import storage
from api.v1.views import api
from flask import abort, jsonify, request, make_response
from flask_restx import Resource, fields
# from api.v1.auth import token_required

@api.route('/todos', strict_slashes=False)
class Todo1(Resource):
    def get(self):
        """ returns list of all todo objects """
        all_todos = []
        todos = storage.all(Todo).values()
        for todo in todos:
            d = todo.to_dict()
            del d['_sa_instance_state']
            print(d)
            all_todos.append(d)
        return jsonify(all_todos)


@api.route('/users/<user_id>/todos', strict_slashes=False)
@api.doc(security='apikey')
class Todo2(Resource):
    resource_fields = api.model('todo', {
        'title': fields.String,
        'isCompleted': fields.Boolean,
    })

    def get(self, user_id):
        """ returns list of all todo objects """

        user = storage.get(User, user_id)
        if not user:
            abort(404)

        todos = []
        all_todos = storage.all(Todo).values()
        for todo in all_todos:
            d = todo.to_dict()
            del d['_sa_instance_state']
            if todo.user_id == user_id:
                todos.append(d)
        return jsonify(todos)

    # @api.doc(params={'title': ''})
    # @api.marshal_with(resource_fields, as_list=True)
    @api.expect(resource_fields)
    def post(self, user_id):
        """ Creates a todo objects """
        data = request.get_json()
        if not data:
            abort(404, 'Not a JSON')
        print(data)
        user = storage.get(User, user_id)
        if not user:
            abort(404)

        todo = Todo(data)
        todo.user_id = user_id
        for k, v in data.items():
            setattr(todo, k, v)
        todo.save()
        t = todo.to_dict()
        del t['_sa_instance_state']
        print(t)
        return make_response(jsonify(t), 201)


@api.route('/todos/<todo_id>', strict_slashes=False)
class Todo3(Resource):
    resource_fields = api.model('todo', {
        'title': fields.String,
        'isCompleted': fields.Boolean,
    })
    def get(self, todo_id):
        """ returns list of all todo objects """
        todo = storage.get(Todo, todo_id)

        if not todo:
            abort(404)

        t = todo.to_dict()
        del t['_sa_instance_state']
        print(t)
        return jsonify(t)

    def delete(self, todo_id):
        """ delete a todo object """
        todo = storage.get(Todo, todo_id)

        if not todo:
            abort(404)

        todo.delete()
        storage.save()
        return make_response(jsonify({}), 200)
    
    @api.expect(resource_fields)
    def put(self, todo_id):
        """ Updates a todo object """
        todo = storage.get(Todo, todo_id)

        if not todo:
            abort(404)

        data = request.get_json()

        if not data:
            return make_response(jsonify({"error": "Not a valid JSON"}), 400)

        for k, v in data.items():
            if k != 'id' and k != 'user_id' and k != 'created_at' and k != 'updated_at':
                setattr(todo, k, v)
        todo.save()
        t = todo.to_dict()
        del t['_sa_instance_state']

        return make_response(jsonify(t), 203)
