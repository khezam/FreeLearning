import os
import click
from forms import RegisterationForm, LoginForm, PostForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, redirect, url_for, request, make_response, session, send_file, render_template, flash, get_flashed_messages, g 

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['FLASKY_ADMIN'] = os.environ.get('FLASKY_ADMIN')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')

def index():
    """
        It turns out that in a sessoin you can only stor a key/value pair and the value can not be another data structure.
        But, you might able to have a data structure as a value if the session in the server-side.
    """
    form = PostForm()
    if form.is_submitted() and form.user_post.data:
        session['posts'] = form.user_post.data +  ', ' + session['posts']
        return redirect(url_for('index_func'))
    print(session)
    return render_template('post.html', form=form, posts=session['posts'].split(','))

app.add_url_rule('/', endpoint='index_func', view_func=index, methods=['GET', 'POST'])

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
    open(os.path.dirname(__file__) + "/names.txt", "w").close()
    return send_file(os.path.dirname(__file__) + '/names.txt', as_attachment=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get('known'):
        return redirect(url_for('index_func'))

    form = LoginForm()
    if request.method == "POST":
        if form.email.data != session.get('email') or not check_password_hash(session.get('password'), form.password.data):
            flash('Invalid email or password', 'error')
        else:
            session['known'] = True
            flash('You have successfully loged in')
            return redirect(url_for('index_func'))
    return render_template('login_page.html', form=form, session=session)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('known'):
        return redirect(url_for('index_func'))

    form = RegisterationForm()
    if form.validate_on_submit():
        if session.get('username') == form.username.data or session.get('email') == form.email.data:
            field = 'username'
            if session.get('email') == form.email.data:
                field = 'email'
            flash(f'This {field} exists already. Please choose a different {field}', 'error')
        else:
            session['username'] = form.username.data
            session['email'] = form.email.data
            session['password'] = generate_password_hash(form.password.data)
            session['posts'] = ''
            session['known'] = False
            flash(f'You have successfully created an account, please login!', 'success')
            return redirect(url_for('login'))
    return render_template('register_page.html', form=form, session=session)

@app.route('/logout')
def logout():
    session['known'] = False 
    return redirect(url_for('login'))

@app.before_request
def is_loged_in():
    if request.endpoint == 'logout' or request.endpoint == 'index_func':
        if not session.get('known'):
            return render_template('login_page.html', form=LoginForm()), 401
    return 

@app.cli.command("test_click")
def test_click():
    """
        This is a customized command line that we could use by flask. The command line containes unitttests that 
        looks for the given firectory and run each file inside it. I read the doc and I did it! :) 
    """
    import unittest 
    tests = unittest.TestLoader().discover(start_dir= os.path.dirname(__file__) + '/tests')
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(tests)

"""
    The url_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
# print(app.url_map)