from flask import Flask, redirect, url_for, request, make_response, session, send_file
import unittest 
# from tests.test_app import ApplicationTest

app = Flask(__name__)
app.config['SECRET_KEY'] = 'lzdifhjeoiwufn'
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
    The set_response veiw fucntion returns back headers that is manually set.
"""
@app.route('/response')
def set_response():
    print(session)
    if session and session['name']:
        return f"<h1>Welcome back, {name}!</h1>"
    if not request.args.get('name'):
        return "<h1>Hello Stranger!</h1>", 200, {'Server': 'Unknown', 'Set_Cookie': 'answer= 42'}
    response = make_response(f"<h1>Hello {request.args.get('name')}</h1>")
    response.set_cookie('answer', '42')
    response.headers['Server'] = 'Unknown'
    session['name'] = request.args.get('name')
    return response

@app.route('/uploads')
def file_pract():
    open("/Users/rogers/Desktop/flasky/names.txt", "w").close()
    return send_file('/Users/rogers/Desktop/flasky/names.txt', as_attachment=True)

@app.cli.command("test_click")
def test_click():
    tests = unittest.TestLoader().discover(start_dir='/Users/rogers/Desktop/flasky/tests')
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(tests)

"""
    The url_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
print(app.url_map)