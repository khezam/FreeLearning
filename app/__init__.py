from flask import Flask
from flask_mail import Mail
from flask_moment import Moment
from flask_migrate import Migrate
from config import Config as config
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap 

db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()
bootstrap = Bootstrap()
moment = Moment()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'danger'


def create_app(config_name=None):
    if not isinstance(config_name, str):
        config_name = ''

    app = Flask(__name__)
    app.config.from_object(config(config_name))
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    bootstrap.init_app(app)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix = '/auth')

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app 