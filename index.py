from flask import Flask, redirect, url_for, request

app = Flask(__name__)

# Added an HTML element to this route.
def index():
    return "<h1>Hello World!</h1>"

app.add_url_rule('/', endpoint='index_func', view_func=index)

# Added a route that fetches the user input appended in the url and display a message with the input of the user.
# The client has to pass a value in the <name> argement and the argumement is passed to view function.
@app.route('/user/<name>')
def user(name):
    return f"<h1>Hello {name}</h1>"

# The below view function is different from the above one. The view function checks if the cleint passes a 
# query string appended in the url
@app.route('/user')
def user_query():
    """
        This is how pass a query string to the url
    """
    if not request.args.get('name'):
        return "<h1>Hello Stranger!</h1>"
    return f"<h1>Hello {request.args.get('name')}</h1>"


# Added another route to see if the endpoint name will by routing to the index view function from the test_endpoint. It worked.
def test_endpoint():
    return redirect(url_for('index_func'))

app.add_url_rule('/home', endpoint='test_func', view_func=test_endpoint)

"""
    The url_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
print(app.url_map)