from functools import wraps
from flask import abort
from flask_login import current_user
from .blueprint_models import Permissions

'''
    I saw the below function from Miguel Grinberg.
'''
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can_user(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permissions.ADMIN)(f)
