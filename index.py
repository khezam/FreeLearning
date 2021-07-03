from flask import Flask 

app = Flask(__name__)

def index():
    return "This is my first app"

app.add_url_rule('/', endpoint='index_fuc', view_func=index)