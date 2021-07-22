import jwt
import hashlib
from time import time 
from datetime import datetime
from flask import current_app, session, request
from . import login_manager, db 
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()

class Permissions:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4 
    MODERATE = 8
    ADMIN = 16

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True) 
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')
    """
    Since SQLAlchemy will set the permissions field to None by default, 
    a class constructor is added that sets it to 0 if an initial value isn’t provided in the constructor arguments.
    """
    def __init__(self, **kwargs): 
        super(Role, self).__init__(**kwargs) 
        if self.permissions is None:
            self.permissions = 0

    def add_permission_to_user(self, permission):
        if not self.user_has_permission(permission):
            self.permissions += permission
        return 
    
    def remove_permission(self, perm): 
        if self.user_has_permission(perm):
            self.permissions -= perm

    def user_has_permission(self, permission):
        if (self.permissions & permission) == permission:
            return True 
        return False

    def user_set_permission(self):
        self.permissions = 0
        return

    """
        Adding roles to the Role table with the permission values. 
    """
    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permissions.FOLLOW, Permissions.COMMENT, Permissions.WRITE],
            'Moderator': [Permissions.FOLLOW, Permissions.COMMENT, Permissions.WRITE, Permissions.MODERATE],
            'Administrator': [Permissions.FOLLOW, Permissions.COMMENT, Permissions.WRITE, Permissions.MODERATE, Permissions.ADMIN]
        }

        for each_role in roles:
            role = Role.query.filter_by(name=each_role).first()
            if not role:
                role = Role(name=each_role)
            role.permissions = 0
            for permission in roles[each_role]:
                role.add_permission_to_user(permission)
            if role.name == 'User':
                role.default = True 
            db.session.add(role)
        db.session.commit()

class User(UserMixin, db.Model):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    

    def __init__(self, **kwargs): 
        super(User, self).__init__(**kwargs) 
        if not self.role:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            else:
                self.role = Role.query.filter_by(default=True).first()
        if self.email and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
    
    def can_user(self, permission):
        if self.role and not self.role.user_has_permission(permission):
            return False 
        return True 
    
    def is_user_administrator(self):
        return self.can_user(Permissions.ADMIN)

    @staticmethod
    def add_user(form):
        user = User(username=form.username.data, email=form.email.data, password_hash=generate_password_hash(form.password.data))
        db.session.add(user)
        return user

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

    def generate_forgot_password_token(self, confirm):
        return self.generate_confirmation_token(confirm)

    def confirm_forgot_password_token(self, token):
        confirmed_token = self.confirm(token, confirm='set_password')
        if not confirmed_token:
            return False
        return True

    @staticmethod
    def insert_user_role():
        admin_role = Role.query.filter_by(name='Administrator').first()
        default_role = Role.query.filter_by(default=True).first()
        users = User.query.all()
        for user in users:
            if not user.role:
                if user.email == current_app.config['FLASKY_ADMIN']:
                    user.role = admin_role
                else:
                    user.role = default_role
            db.session.add(user)
        db.session.commit()

    def ping(self):
        self.last_seen = datetime.utcnow() 
        db.session.add(self) 
        db.session.commit()

    def is_administrator(self):
        return self.can_user(Permissions.ADMIN)

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'http://www.gravatar.com/avatar'
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        hash = self.avatar_hash
        if not hash:
            self.avatar_hash = self.gravatar_hash()
            db.session.add(self)
            db.session.commit()
        return f"{url}/{hash}?s={size}&d={default}&r={rating}"

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
    
    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser  