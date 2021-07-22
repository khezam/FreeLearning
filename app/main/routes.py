from . import main 
from .forms import PostForm
from ..blueprint_models import User
from flask_login import login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for, request, session, render_template, flash, get_flashed_messages, current_app

def index():
    """
        It turns out that in a sessoin you can only stor a key/value pair and the value can not be another data structure.
        But, you might able to have a data structure as a value if the session in the server-side.
    """
    form = PostForm()
    if form.is_submitted() and form.user_post.data:
        session['posts'] = form.user_post.data +  ',' + session.get('posts', default='')
        return redirect(url_for('main.index_func'))
    return render_template('main/post.html', form=form, posts=session.get('posts', default='').split(','))

main.add_url_rule('/', endpoint='index_func', view_func=index, methods=['GET', 'POST'])

# @main.route('/logout')
# @login_required
# def logout():
#     session['known'] = False
#     session['posts'] = ''
#     flash('You have been logged out.', 'success')
#     logout_user()
#     return redirect(url_for('auth.login'))

# @main.route('/reset-password', methods=['GET', 'POST'])
# @login_required
# def reset_password():
#     form = ResetPassword()
#     if form.validate_on_submit():
#         user = User.query.filter_by(id=session.get('_user_id')).first()
#         user.set_password = form.new_password.data
#         db.session.commit()
#         flash('Your password has been reset.', 'success')
#         return redirect(url_for('main.index_func'))
#     return render_template('main/edit_password.html', form=form)

@main.route('/user-profile/<username>')
@login_required
def user_profile(username):
    from hashlib import md5 
    user = User.query.filter_by(username=username).first_or_404()
    session['user_avatar'] = md5(b'{user.email}').hexdigest()
    return render_template('user.html', posts=session.get('posts', default='').split(','), user=user)