from ..blueprint_models import User
from flask import session, flash 
from flask_wtf import FlaskForm
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, BooleanField, TextAreaField

class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20, message='Invalid email or password')])
    remember_me = BooleanField(label='Remember', default=False)
    submit = SubmitField(label='Submit', validators=[DataRequired()])

class RegisterationForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired(), Length(min=5, max=20)])
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20)])
    confirm_password = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo(fieldname='password', message='Passwords do not match')])
    remember_me = BooleanField(label='Remember', default=False)
    submit = SubmitField(label='Submit')

    def validate_username(form, field):
        user = User.query.filter_by(username=field.data).first()
        if user and user.username == field.data:
                raise ValueError ('[This username exists already. Please choose a different username]')
            
    def validate_email(form, field):
        user = User.query.filter_by(email=field.data).first()
        if user and user.email == field.data:
                raise ValueError ('[This email exists already. Please choose a different email]')

class ForgotPassword(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    submit = SubmitField(label='Submit')

    def validate_old_password(form, field):
        user = User.query.filter_by(email=field.data)
        if not user:
            raise ValueError ('[Invalid email]')

class NewPassword(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=60), Email()])
    new_password = PasswordField(label='New Password', validators=[DataRequired(), Length(min=5, max=20)])
    submit = SubmitField(label='Submit') 