from ..blueprint_models import User
from flask import session, flash 
from flask_wtf import FlaskForm
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, BooleanField, TextAreaField

class PostForm(FlaskForm):
    user_post = TextAreaField(label='Post', validators=[DataRequired()])
    submit = SubmitField(label='Submit')
