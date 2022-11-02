from models.user import User
from models import storage
from api.v1.views import app_views
from flask import jsonify, make_response


@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status():
    """ Status of API """
    return jsonify({"status": "OK"})


@app_views.route('/stats', methods=['GET'])
def get_stats():
    '''Get number of each objects by type'''
    stats = {}
    classes = {
        # "Amenity": "amenities",
        # "City": "cities",
        # "Place": "places",
        # "Review": "reviews",
        "Todo": "todos",
        "User": "users"}
    for cls in classes:
        count = storage.count(cls)
        stats[classes[cls]] = count
    return jsonify(stats)
