from flask import Flask 

app = Flask(__name__)

def index():
    return "This is my first app"

app.add_url_rule('/', endpoint='index_func', view_func=index)

"""
    The ur_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
print(app.url_map)