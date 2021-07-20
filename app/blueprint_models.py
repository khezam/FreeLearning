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

    def generate_confirmation_token(self, expires_in=600):
        token = jwt.encode({'confirm': self.id, 'exp': time() + expires_in}, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token

    def confirm(self, token):
        try:
            confirmed_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return False 
    
        if self.id != confirmed_token.get('confirm'):
            return False 
        
        # session['confirm'] = True
        self.confirmed = True 
        return True 
