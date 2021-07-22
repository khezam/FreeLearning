from flask import Blueprint

main = Blueprint('main', __name__)

from . import routes, errors, forms
from ..blueprint_models import Permissions 

@main.app_context_processor
def inject_permissions():
    return dict(Permissions=Permissions)