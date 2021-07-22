import jwt
from . import auth
from app import db, mail
from ..email import send_email
from flask_mail import Message
from ..blueprint_models import User
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from .forms import RegisterationForm, LoginForm, ForgotPassword, NewPassword, ReconfirmToken, UpdatePassword, ChangeEmailRequest
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
    print(current_user.can(1))
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func')) 

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and not user.confirmed:
            flash('Your account has not been confirmed. Please, confirm your account and try again.', 'danger')
            return render_template('auth/unconfirmed.html', username=user.username)
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, form.remember_me.data)
            session['known'] = True
            flash('You have successfully logged in.', 'success')
            return redirect(url_for('main.index_func'))
        flash('Invalid email or password.', 'danger')
    return render_template('auth/login_page.html', form=form, session=session)

def send_token(subject, token, username=None, user_id=None):
    session['confirm'] = False
    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=['flaskyproject@gmail.com'])
    msg.html = render_template('token.html', name=username, token=token, user_id=user_id)
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
        token = user.generate_confirmation_token('confirm')
        session['id'] = user.id
        session['posts'] = ''
        session['known'] = False
        send_email(form.email.data, "Account confirmation", 'auth/email/token', token=token, username=form.username.data, user_id=user.id)
        flash('A confirmation email has been sent to you by email, please confirm!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register_page.html', form=form, session=session)

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func'))

    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('This email is invalid. Please enter a valid email.', 'danger')
            return redirect(url_for('auth.login'))
        token = user.generate_forgot_password_token('set_password')
        session['forgot_password'] = True
        send_email(form.email.data, "Password Reset!", 'auth/email/forgot_password', token=token, username=user.username, user_id=user.id) 
        #send_email("Password Reset!", token=token, username=user.username, user_id=user.id)
        flash('An email has been sent to you. Please check your email', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/forgot_password.html', form=form)

@auth.route('/forgot_password/<user_id>/<token>', methods=['GET', 'POST'])
def confirm_forgot_password_token(user_id, token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func'))

    user = User.query.filter_by(id=user_id).first()
    if not user or not user.confirm_forgot_password_token(token):
        flash('Invalid request.', 'danger')
        return redirect(url_for('auth.login'))
    flash('You have confirmed your account. Thanks!', 'success')
    form = NewPassword()
    if form.validate_on_submit():
        user.set_password = form.new_password.data
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/new_password.html', form=form)

@auth.route('/confirm/<user_id>/<token>', methods=['GET', 'POST'])
def confirm_token(user_id, token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func'))
    
    user = User.query.filter_by(id=user_id).first()
    if user and user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
        # if session.get('forgot_password'):
        #     form = NewPassword()
        #     if form.validate_on_submit():
        #         user.set_password = form.new_password.data
        #         db.session.commit()
        #         flash('Your password has been reset.', 'success')
        #     else:
        #         return render_template('auth/new_password.html', form=form)
    else:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('auth.login'))

@auth.route('/reconfirm_token', methods=['GET', 'POST'])
def reconfirm_token():
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func'))

    form = ReconfirmToken()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_confirmation_token('confirm')
            send_email(form.email.data, "Account confirmation", 'auth/email/token', token=token, username=user.username, user_id=user.id)
            flash('A confirmation email has been sent to you by email, please confirm!', 'success')
        else:
            flash('Invalid email', 'danger')
        return redirect(url_for('auth.login'))
    return render_template('auth/reconfirm.html', form=form)

@auth.route('/update-password', methods=['GET', 'POST'])
@login_required
def update_password():
    form = UpdatePassword()
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.old_password.data):
            current_user.set_password = form.new_password.data
            db.session.commit()
            flash('Your password has been updated.', 'success')
            return redirect(url_for('main.index_func'))
        flash('Invalid passwords.', 'danger')
    return render_template('auth/update_password.html', form=form)

@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailRequest()
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.password.data) and current_user.email == form.old_email.data.lower():
            if current_user.email != form.new_email.data:
                token = current_user.generate_email_change_token('change_email', new_email=form.new_email.data)
                send_email(form.new_email.data, "Account confirmation", 'auth/email/change_email', token=token, username=current_user.username, user_id=current_user.id)
                db.session.commit()
                flash('A confirmation email has been sent to you by email, please follow the instructions and confirm!', 'success')
                return redirect(url_for('main.index_func'))
            flash('The new email already exists. Please try again.', 'warning')    
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('auth/change_email.html', form=form)

@auth.route('/change-email/<token>')
@login_required
def confirm_change_email_token(token):
    if current_user.confirm_email_change_token(token):
        db.session.commit()
        flash('Your email has been changed.', 'success')
    else:
        flash('Invalid email request', 'danger')
    return redirect(url_for('main.index_func'))

@auth.route('/logout')
@login_required
def logout():
    session['known'] = False
    session['posts'] = ''
    flash('You have been logged out.', 'success')
    logout_user()
    return redirect(url_for('auth.login'))
