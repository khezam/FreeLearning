from flask_wtf import FlaskForm
from flask import session, flash
from wtforms import ValidationError
from ..blueprint_models import User
from wtforms.fields.html5 import EmailField
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, EqualTo, Length, Email, Regexp
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField

class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=64), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20)])
    remember_me = BooleanField(label='Keep me logged in', default=False)
    submit = SubmitField(label='Log In', validators=[DataRequired()])

class RegisterationForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired(), Length(min=5, max=20), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20)])
    confirm_password = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo(fieldname='password', message='Passwords do not match')])
    submit = SubmitField(label='Register')

    def validate_username(form, field):
        user = User.query.filter_by(username=field.data).first()
        if user and user.username == field.data:
                raise ValidationError ('This username exists already. Please choose a different username')
            
    def validate_email(form, field):
        user = User.query.filter_by(email=field.data).first()
        if user and user.email == field.data:
                raise ValidationError ('This email exists already. Please choose a different email')

class ForgotPassword(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    submit = SubmitField(label='Submit')

    def validate_old_password(form, field):
        user = User.query.filter_by(email=field.data)
        if not user:
            raise ValidationError ('Invalid email')

class NewPassword(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=64), Email()])
    new_password = PasswordField(label='New Password', validators=[DataRequired(), Length(min=5, max=20)])
    submit = SubmitField(label='New Password') 

class ReconfirmToken(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    submit = SubmitField(label='Submit')

    def validate_old_password(form, field):
        user = User.query.filter_by(email=field.data)
        if not user:
            raise ValidationError ('Invalid email')

class UpdatePassword(FlaskForm):
    new_password = PasswordField(label='New Password', validators=[DataRequired(), Length(min=5, max=20)])
    old_password = PasswordField(label='Old Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

class ChangeEmailRequest(FlaskForm):
    new_email = EmailField(label='New Email', validators=[DataRequired(), Length(min=5, max=64), Email()])
    old_email = EmailField(label='Old Email', validators=[DataRequired(), Length(min=5, max=64), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20)])
    submit = SubmitField(label='Submit')

    def validate_new_email(form, field):
        user = User.query.filter_by(email=field.data).first()
        if user and user.email == field.data:
            flash('The new email already exists. Please try again.', 'warning')
            raise ValidationError ('This email already exists. Please try again')
