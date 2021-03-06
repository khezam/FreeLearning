import os 
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    FLASKY_ADMIN = os.getenv('FLASKY_ADMIN')
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = os.getenv('MAIL_PORT')
    FLASKY_MAIL_SUBJECT_PREFIX = 'FreeLearning'
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS').lower() in ['true', 'on', '1']
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASKY_POSTS_PER_PAGE = 20
    FLASKY_FOLLOWERS_PER_PAGE = 50
    FLASKY_COMMENTS_PER_PAGE = 30
    WTF_CSRF_ENABLED = False

    def __new__(cls, config=None):
        url = ''
        if config == 'testing_config':
            url = 'T'
            cls.TESTING = True
        elif config == 'production_config':
            url = 'P'
        cls.SQLALCHEMY_DATABASE_URI = os.getenv('URL' + url)
        return cls