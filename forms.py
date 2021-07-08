from flask import session, flash 
from flask_wtf import FlaskForm
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, BooleanField, TextAreaField

class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=20), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20)])
    remember_me = BooleanField(label='Remember', default=False)
    submit = SubmitField(label='Submit', validators=[DataRequired()])

class RegisterationForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired(), Length(min=5, max=20)])
    email = EmailField(label='Email', validators=[DataRequired(), Length(min=5, max=20), Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=5, max=20)])
    confirm_password = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo(fieldname='password', message='Passwords do not match')])
    remember_me = BooleanField(label='Remember', default=False)
    submit = SubmitField(label='Submit')

    def validate_username(form, field):
        if field.data == session.get('username'):
            raise ValueError ('[This username exists already. Please choose a different username]')
            
    def validate_email(form, field):
        if field.data == session.get('email'):
            raise ValueError ('[This email exists already. Please choose a different email]')       

class PostForm(FlaskForm):
    user_post = TextAreaField(label='Post')
    submit = SubmitField(label='Submit')