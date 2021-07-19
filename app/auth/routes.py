import jwt
from . import auth
from app import db, mail
from flask_mail import Message
from ..blueprint_models import User
from .forms import RegisterationForm, LoginForm, ForgotPassword, NewPassword
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, current_user
from flask import redirect, url_for, request, make_response, session, send_file, render_template, flash, get_flashed_messages, abort, current_app

# @auth.route("/login", methods=["GET", "POST"])
# def login():
#     if session.get('known'):
#         return redirect(url_for('main.index_func')) 

#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if not user or not check_password_hash(user.password_hash, form.password.data) or user.email != form.email.data:
#             flash('Invalid email or password', 'error')
#         else:
#             login_user(user, remember=form.remember_me.data)
#             session['known'] = True
#             flash('You have successfully loged in')
#             return redirect(url_for('main.index_func'))
#     return render_template('login_page.html', form=form, session=session)

@auth.route("/login", methods=["GET", "POST"])
def login():
    if session.get('known'):
        return redirect(url_for('main.index_func')) 

    form = LoginForm()
    if form.validate_on_submit() and session.get('confirm'):
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            print(form.remember_me.data)
            login_user(user, form.remember_me.data)
            print(session.get('_token'))
            session['known'] = True
            flash('You have successfully logged in.', 'success')
            return redirect(url_for('main.index_func'))
    if request.method == 'POST':
        if not session.get('confirm'):
            flash('Your account has not been confirmed. Please, confirm your aacount and try again.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('auth/login_page.html', form=form, session=session)

def send_token(subject, username=None):
    token = jwt.encode({'confirm': True}, current_app.config['SECRET_KEY'], algorithm='HS256')
    # session['token'] = token
    session['confirm'] = False
    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
    msg.html = render_template('token.html', name=username, token=token)
    mail.send(msg)
    return 

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('known'):
        return redirect(url_for('main.index_func'))

    form = RegisterationForm()
    if form.validate_on_submit():
        user = User.add_user(form)
        db.session.commit()
        session['id'] = user.id
        session['posts'] = ''
        session['known'] = False
        send_token("Account confirmation", form.username.data)
        flash(f'An email has been sent to your account, please confirm!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register_page.html', form=form, session=session)

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data)
        if not user:
            redirect(url_for('auth.login'))
        session['forgot_password'] = True 
        send_token("Password Reset!")
        flash('An email has been sent to you. Please check your email')
        return redirect(url_for('auth.login'))
    return render_template('auth/forgot_password.html', form=form)

# @auth.route('/confirm/<token>')
# def confirm_token(token):
#     try:
#         confirm = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
#         session_token = jwt.decode(session.get('token'), current_app.config['SECRET_KEY'], algorithms=['HS256'])
#         session['confirm'] = True
#     except:
#         flash('This token is invalid')
#         return redirect(url_for('auth.login'))
#     if not session.get('known') and not session.get('forgot_password'):
#         return redirect(url_for('auth.login'))
#     return redirect(url_for('auth.new_password'))

@auth.route('/confirm/<token>', methods=['GET', 'POST'])
def confirm_token(token):
    try:
        confirm = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        # session_token = jwt.decode(session.get('token'), current_app.config['SECRET_KEY'], algorithms=['HS256'])
        session['confirm'] = True
    except:
        flash('This token is invalid')
        return redirect(url_for('auth.login'))
    if not session.get('known') and not session.get('forgot_password'):
        return redirect(url_for('auth.login'))

    form = NewPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        user.set_password = form.new_password.data
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('auth.login'))
    return render_template('auth/new_password.html', form=form)

# @auth.route('/new_password', methods=['GET', 'POST'])
# def new_password():
#     if not session.get('confirm'):
#         flash('You have not confirmed youe account. Please, try again')
#         return redirect(url_for('auth.login'))
    
#     form = NewPassword()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         user.set_password = form.new_password.data
#         db.session.commit()
#         send_token('New Password')
#         flash('Your password has been reset.')
#         return redirect(url_for('auth.login'))
#     return render_template('auth/new_password.html', form=form)