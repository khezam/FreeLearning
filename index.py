import os
import jwt
import click
import psycopg2
from flask_migrate import Migrate
from flask_mail import Message, Mail
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, redirect, url_for, request, make_response, session, send_file, render_template, flash, get_flashed_messages, g, abort
from config import Config as config 

app = Flask(__name__)
# app.config.from_object(config())
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['FLASKY_ADMIN'] = os.getenv('FLASKY_ADMIN')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
# db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
app.login_view = 'login'
from models import User, Role
from forms import RegisterationForm, LoginForm, PostForm, ResetPassword, ForgotPassword, NewPassword

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

def index():
    """
        It turns out that in a sessoin you can only stor a key/value pair and the value can not be another data structure.
        But, you might able to have a data structure as a value if the session in the server-side.
    """
    form = PostForm()
    if form.is_submitted() and form.user_post.data:
        session['posts'] = form.user_post.data +  ',' + session.get('posts', default='')
        return redirect(url_for('index_func'))
    print(session.get('posts', default='').split(','))
    print(User.query.all())
    return render_template('post.html', form=form, posts=session.get('posts', default='').split(','))

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
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not check_password_hash(user.password_hash, form.password.data) or user.email != form.email.data:
            flash('Invalid email or password', 'error')
        else:
            login_user(user, remember=form.remember_me.data)
            session['known'] = True
            flash('You have successfully loged in')
            return redirect(url_for('index_func'))
    return render_template('login_page.html', form=form, session=session)

def send_email(name):
    msg = Message("Welcome!", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
    msg.html = render_template('mail.html', name=name)
    mail.send(msg)
    return

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('known'):
        return redirect(url_for('index_func'))

    form = RegisterationForm()
    if form.validate_on_submit():
        user = User.add_user(form)
        db.session.commit()
        session['id'] = user.id
        session['posts'] = ''
        session['known'] = False
        # send_email(form.username.data)
        flash(f'An email has been sent to your account, please confirm!', 'success')
        return redirect(url_for('login'))
    return render_template('register_page.html', form=form, session=session)

@app.route('/logout')
@login_required
def logout():
    session['known'] = False
    session['posts'] = ''
    logout_user()
    return redirect(url_for('login'))

@app.before_request
def is_loged_in():
    """
        Using a hook function to check if the user is logged in. Later we will see how to use
        flask login manager.
    """
    authenticated_routes = {'logout', 'index_func', 'reset_password', 'user_profile'}
    if request.endpoint in authenticated_routes:
        print('it came here')
        if not session.get('known'):
            flash("You need to log in", "error")
            return render_template('login_page.html', form=LoginForm()), 401
    return 

@app.route('/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    form = ResetPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(id=session.get('_user_id')).first()
        user.set_password = form.new_password.data
        db.session.commit()
        flash('Your password has been reseted.')
        return redirect(url_for('index_func'))
    return render_template('edit_password.html', form=form)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        token = jwt.encode({'confirm': True}, app.config['SECRET_KEY'], algorithm='HS256')
        session['token'] = token
        msg = Message("Password Reset!", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
        msg.html = render_template('token.html', name=user.username, token=token)
        mail.send(msg)
        flash('An email has been sent to you. Please check your email')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/confirm/<token>')
def confirm_token(token):
    try:
        confirm = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        session_token = jwt.decode(session.get('token'), app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        flash('This is token is invalid')
        return redirect(url_for('forgot_password'))
    return redirect(url_for('new_password'))

@app.route('/new_password', methods=['GET', 'POST'])
def new_password():
    form = NewPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        user.set_password = form.new_password.data
        db.session.commit()
        flash('Your password has been reseted.')
        return redirect(url_for('login'))
    return render_template('new_password.html', form=form)
        


@app.route('/user-profile/<username>')
@login_required
def user_profile(username):
    from hashlib import md5 
    user = User.query.filter_by(username=username).first_or_404()
    session['user_avatar'] = md5(b'{user.email}').hexdigest()
    return render_template('user.html', posts=session.get('posts', default='').split(','), user=user)
    
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

@app.shell_context_processor
def make_shell_context():
    """
        Rather than importing the objects of the databse, Flask gives the ability to automate this 
        by useing shell context processor.
    """
    return dict(db=db, User=User, Role=Role)

"""
    The url_map is a pointer of the struct Map. I used the pointer to see the route 
    that I created manually with given endpoint name 'index_func'
""" 
# print(app.url_map)