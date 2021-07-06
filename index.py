from flask import Flask, redirect, url_for, request, make_response, session, send_file, render_template, flash, get_flashed_messages
import unittest 
import click 



app = Flask(__name__)
app.config['SECRET_KEY'] = 'lzdifhjeoiwufn'

def index():
    if not session.get('known'):
        return redirect(url_for('login'))
    return render_template('base.html', username=session.get('username'))

app.add_url_rule('/', endpoint='index_func', view_func=index)

@app.route('/user/<name>')
def user(name):
    # Added a route that fetches the user input appended in the url and display a message with the input of the user.
    # The client has to pass a value in the <name> argement and the argumement is passed to view function.
    return f"<h1>Hello {name}</h1>"

@app.route('/user')
def user_query():
    # The view function is different from the above one. The view function checks if the cleint passes a 
    # query string appended in the url
    """
        This is how pass a query string to the url
    """
    return render_template('base.html', name=request.args.get('name'))

def test_endpoint():
    # Added another route to see if the endpoint name will by routing to the index view function from the test_endpoint. It worked.
    return redirect(url_for('index_func'))

app.add_url_rule('/home', endpoint='test_func', view_func=test_endpoint)

@app.route('/response')
def set_response():
    """
    The set_response veiw fucntion returns back headers that is manually set.
    """
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get('known'):
        return redirect(url_for('index_func'))

    if request.method == "POST":
        if request.form.get('email') != session.get('email') or request.form.get('username') != session.get('username'):
            flash('Invalid username or email', 'error')
        else:
            session['known'] = True
            flash('You have successfully loged in')
            return redirect(url_for('index_func'))
    return render_template('login_page.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('known'):
        return redirect(url_for('index_func'))

    if request.method == 'POST':
        if session.get('username') == request.form.get('username') or session.get('email') == request.form.get('email'):
            field = 'username'
            if session.get('email') == request.form.get('email'):
                field = 'email'
            flash(f'This {field} exists already. Please choose a different {field}', 'error')
        else:
            session['username'] = request.form.get('username')
            session['email'] = request.form.get('email')
            session['known'] = False
            return redirect(url_for('login'))
    return render_template('register_page.html')

@app.route('/logout')
def logout():
    if not session.get('known'):
        return redirect(url_for('login'))
    session['known'] = False 
    return redirect(url_for('login'))


@app.cli.command("test_click")
def test_click():
    """
        This is a customized command line that we could use by flask. The command line containes unitttests that 
        looks for the given firectory and run each file inside it. I read the doc and I did it! :) 
    """
    import os
    tests = unittest.TestLoader().discover(start_dir= os.path.dirname(__file__) + '/tests')
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(tests)

"""
    The url_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
# print(app.url_map)