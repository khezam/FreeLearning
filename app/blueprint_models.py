import jwt
from time import time
from flask import current_app, session
from . import login_manager, db 
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

class User(UserMixin, db.Model):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)

    @staticmethod
    def add_user(form):
        user = User(username=form.username.data, email=form.email.data, password_hash=generate_password_hash(form.password.data))
        db.session.add(user)
        return user

    # def update_user(self, **kwargs):
    #     for field in kwargs:
    #         if field in self.__dict__:
    #             if filed == 'username':
    #                 self.username = kwargs[field]
    #             elif field == 'email':
    #                 self.email = kwargs[field]
    #             else:
    #                 self.confirmed = kwargs[field]
    #     db.session.add(self)
    #     return 

    @property
    def set_password(self):
        raise AttributeError('set password is not a readable attribute')

    @set_password.setter
    def set_password(self, new_password):
        self.password_hash = generate_password_hash(new_password)
        db.session.add(self)
        return

    def generate_confirmation_token(self, confirm, expires_in=600, **kwargs):
        if kwargs:
            for field in kwargs:
                token = jwt.encode({confirm: self.id, field: kwargs[field], 'exp': time() + expires_in}, current_app.config['SECRET_KEY'], algorithm='HS256')
                break 
        else:
            token = jwt.encode({confirm: self.id, 'exp': time() + expires_in}, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token

    def confirm(self, token, confirm='confirm'):
        try:
            confirmed_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return False 

        print(f'Here is the token:{confirmed_token}')
        if self.id != confirmed_token.get(confirm):
            return False 

        if confirm != 'confirm':
            return confirmed_token

        self.confirmed = True 
        return True 

    def generate_email_change_token(self, confirm, new_email):
        return self.generate_confirmation_token(confirm, new_email=new_email)

    def confirm_email_change_token(self, token):
        new_email = self.confirm(token, confirm='change_email')
        if not new_email or self.query.filter_by(email=new_email.get('new_email')).first():
            return False
        self.email = new_email.get('new_email')
        db.session.add(self)
        return True
