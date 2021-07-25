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

"""
    @login view function: This view function validates if the method of the request is 
    a post request message and if th form is validated, then do:
        if the user is already logged in, then do:
            1- redirect redirect the user to the view function named index_func registered in the blueprint named main
            2- return
        if the user's account is confirmed in the database:
            return back a message to the user that they need to confirm their account
        if the user exists and the password evaluates to true(hashed password and user's password input), then do:
            1- login the user and the user's id and a uinque ident in the session
            2- flash the user with a message
            3- redirect the user to the view function named index_func registered in the blueprint named main
        otherwise:
            flash a user with a message
        send a response message back that is a type of html. 
"""
@auth.route("/login", methods=["GET", "POST"])
def login():
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
            flash('You have successfully logged in.', 'success')
            return redirect(url_for('main.index_func'))
        flash('Invalid email or password.', 'danger')
    return render_template('auth/login_page.html', form=form, session=session)

"""
    @register view function: 
    if the current user is already logged in:
        1- redirect the user to the view function named index_func registered in the blueprint named main
        2- return
    
    declare a pointer variable named form and assign the pointer of the class named RegisterationForm to it.
    if the method of the request message is POST and the form is validated, do the following:
        1- add the user in the database session
        2- commit the user to the database 
        3- generate a token and assign it to the variable named token 
        4- send an email to the user's email 
        5- let the user know an email has been sent to their email to confirm their account.
        6- redirect the the user to the login endpoint that is registered to blueprint named auth
    otherwise, do the following:
        return back the registration form to the user that is a type of html.
"""
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func')) 

    form = RegisterationForm()
    if form.validate_on_submit():
        user = User.add_user(form)
        db.session.commit()
        token = user.generate_confirmation_token('confirm')
        send_email(form.email.data, "Account confirmation", 'auth/email/token', token=token, username=form.username.data, user_id=user.id)
        flash('A confirmation email has been sent to you by email, please confirm!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register_page.html', form=form, session=session)

"""
    @forgot_password_request:
    if the current user is already logged in:
        1- redirect the user to the view function named index_func registered in the blueprint named main
        2- return
    
    declare a pointer variable named form and assign the pointer of the class named ForgotPassword to it.
    if the form is evaluated to true and the method of the request message is POST, then do the following:
        1- fetch the user from the databse and assign it to the pointer variable named user 
        2- if the user does not exit, do the following:
            1- flash the user that the email is not valid
            2- redirect the user to login endpoint that is registered to the blueprint named auth

        othewise, do the following:
            1- generate a token that contains a key named set_password and assign it to the pointer variable named token
            2- send an email to the user's email
            3- let the user know an email has been sent to their email to confirm their account.
            4- redirect the the user to the login endpoint that is registered to blueprint named auth
    
    otherwise, do the folloing:
        return back to the user a response message that is a type of html which is a form 
"""
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

"""
    @confirm_forgot_password_token:
    if the current user is already logged in:
        1- redirect the user to the view function named index_func registered in the blueprint named main
        2- return 

    otherwise, do the folloing:
        1- get the user from the database and assign it to the pointer variable named user 
        if the user does not exist or the token evaluates to false, then do the following:
            Note: (the pointer varibale named user is a pointer that is a type of the class named User. 
            part of the class is a method named confirm_forgot_password_token that validates if the token 
            valid.)
            1- send a message to the user the request is invalid.
            2- redirect the user to login endpoint that is registered to the blueprint named auth
        
        otherwise, do the folloing:
            declare a pointer variable named form and assign the pointer of the class named confirm_forgot_password_token to it.
            1- if the method of the request message is POST and the form is validated, then do the following:
                1- overwrite the password in the database with current password by invoking the method named set_password
                2- flash th user that the password is has been reset
                3- redirect the the user to the login endpoint that is registered to blueprint named auth
                4- return which means get the fuck out of the view function.       
"""
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

"""
    @confirm_token: This view function checks if the token is validate and not modified.
    if the current user already logged in, then do the following:
        1- redirect the user to the index_func endpoint that is registered to the main blueprint.
        2- exit the function

    otherwise, do the following:
        1- fetch the user from the database and assign to pointer variable named user.
        2- if the user exists and the token is confirmed:
            flash the user that their account has been confirmed.
        otherwise, do the following:
            flash the user that their account has not been confirmed.
    redirect the user to the endpoint named login that is registered to auth blueprint
    exist out of the function
"""
@auth.route('/confirm/<user_id>/<token>', methods=['GET', 'POST'])
def confirm_token(user_id, token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index_func'))
    
    user = User.query.filter_by(id=user_id).first()
    if user and user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('auth.login'))

"""
    @reconfirm_token: This view function resend a token to the user for account confirmation
    if the current user already logged in, then do the following:
        1- redirect the user to the index_func endpoint that is registered to the main blueprint.
        2- exit the function
    otherwise, do the following:
        1- instanciate the class named ReconfirmToken and assign to pointer varibale named form
        2- if the method of the request message is POST and the form is validate, then do the following:
            1- fetch the user by email from the database and assign the pointer to the pointer variable named user
            2- if the user evaluates to true, then do the following:
                1- derafrance the class named User and invoke the method named generate_confirmation_token to create a token
                2- send an email to user so they confirm their account
                3- flash the damn user.
            otherwise, do the following:
                1- flash the user that the email is invalid
        send back to the user a response message that is a type of html
        return 
"""
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

""" 
    @update_password: This view function lets the user update their password
    1- create an instance and assign to the pointer variable named form
    2- if the method is POST and the form is validate, then do the following:
        1- if the current user's password(hashed) in the database is equal to the the user's input, then do the following:
            1- invoke the method named set_password and set the new password 
            2- commit it to the database
            3- flash the user 
            4- redirect the user to th endpoint named index_func that is registered to main blueprint
            4- return
    otherwise,
        flash the user 
    send a response message to the user 
    return 
"""
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

"""
    @change_email_request: This veiw function let the user to change their email while logged in
    the @login_required is a flask login manager extension that makes the user is logged in.
    1- create an instance and assign it to the pointer variable named form
    2- if the method of the request message is POST and the form is validated, then do the following:
        1- if the password and the email stored in the database are equal to the user's input of password and email:
            1- if the current emila is not equal to the new email, do th following:
                1- generate a token
                2- send an email to the user
                3- flash the user 
                4- commit the changes to the database
                5- redirect the usr to the endpoit named index_func
                6- return 
        otherwise, dow the following:
            flash the user that their email is invalid
    return a response message to the user that is a type of html
"""
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
    flash('You have been logged out.', 'success')
    logout_user()
    return redirect(url_for('auth.login'))
