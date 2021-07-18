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

class ResetPassword(FlaskForm):
    new_password = PasswordField(label='New Password', validators=[DataRequired(), Length(min=5, max=20)])
    old_password = PasswordField(label='Old Password', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

    def validate_old_password(form, field):
        user = User.query.filter_by(id=session.get('_user_id')).first()
        if not check_password_hash(user.password_hash, field.data):
            raise ValueError ('[Invalid passwords]')
