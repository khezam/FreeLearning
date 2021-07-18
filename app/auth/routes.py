from . import auth
from app import db
from ..blueprint_models import User
from .forms import RegisterationForm, LoginForm, ForgotPassword
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, current_user
from flask import redirect, url_for, request, make_response, session, send_file, render_template, flash, get_flashed_messages, abort, current_app

@auth.route("/login", methods=["GET", "POST"])
def login():
    if session.get('known'):
        return redirect(url_for('main.index_func')) 

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user or not check_password_hash(user.password_hash, form.password.data) or user.email != form.email.data:
            flash('Invalid email or password', 'error')
        else:
            login_user(user, remember=form.remember_me.data)
            session['known'] = True
            flash('You have successfully loged in')
            return redirect(url_for('main.index_func'))
    return render_template('login_page.html', form=form, session=session)

def send_email(name):
    msg = Message("Welcome!", sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
    msg.html = render_template('mail.html', name=name)
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
        # send_email(form.username.data)
        flash(f'An email has been sent to your account, please confirm!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register_page.html', form=form, session=session)

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        token = jwt.encode({'confirm': True}, current_app.config['SECRET_KEY'], algorithm='HS256')
        session['token'] = token
        msg = Message("Password Reset!", sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
        msg.html = render_template('token.html', name=user.username, token=token)
        mail.send(msg)
        flash('An email has been sent to you. Please check your email')
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html', form=form)

@auth.route('/confirm/<token>')
def confirm_token(token):
    try:
        confirm = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        session_token = jwt.decode(session.get('token'), current_app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        flash('This is token is invalid')
        return redirect(url_for('auth.forgot_password'))
    return redirect(url_for('new_password'))

@auth.route('/new_password', methods=['GET', 'POST'])
def new_password():
    form = NewPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        user.set_password = form.new_password.data
        db.session.commit()
        flash('Your password has been reseted.')
        return redirect(url_for('auth.login'))
    return render_template('new_password.html', form=form)