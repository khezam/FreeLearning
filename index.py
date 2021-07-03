from flask import Flask, redirect, url_for

app = Flask(__name__)

def index():
    return "This is my first app"

app.add_url_rule('/', endpoint='index_func', view_func=index)


# Added another route to see if the endpoint name will by routing to the index view function from the test_endpoint. It worked.
def test_endpoint():
    return redirect(url_for('index_func'))

app.add_url_rule('/home', endpoint='test_func', view_func=test_endpoint)

"""
    The url_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
print(app.url_map)