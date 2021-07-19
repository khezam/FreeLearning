import os 
import psycopg2
from app import create_app, db
from app.blueprint_models import User, Role
from flask import render_template, request, session, flash, redirect, url_for
from flask_migrate import Migrate

app = create_app()
migrate = Migrate(app, db)

@app.cli.command("test_click")
def test_click():
    """
        This is a customized command line that we could use by flask. The command line containes unitttests that 
        looks for the given firectory and run each file inside it. I read the doc and I did it! :) 
    """
    import unittest 
    tests = unittest.TestLoader().discover(start_dir= os.path.dirname(__file__) + '/tests')
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(tests)

@app.shell_context_processor
def make_shell_context():
    """
        Rather than importing the objects of the databse, Flask gives the ability to automate this 
        by useing shell context processor.
    """
    return dict(db=db, User=User, Role=Role)

@app.before_request
def is_loged_in():
    """
        Using a hook function to check if the user is logged in. Later we will see how to use
        flask login manager.
    """
    authenticated_routes = {'auth.logout', 'main.index_func', 'main.reset_password', 'main.user_profile'}
    if request.endpoint in authenticated_routes:
        print('it came here')
        if not session.get('known'):
            flash("You are not logged in. Please, log in.", "danger")
            # return render_template('app/login_page.html', form=LoginForm()), 401
            return redirect(url_for('auth.login'))
    return 