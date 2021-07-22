from . import main
from .. import db
from ..decorators import admin_required
from .forms import PostForm, EditProfileForm, EditProfileAdminForm
from ..blueprint_models import User, Role, Permissions, Post
from flask_login import login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for, request, session, render_template, flash, get_flashed_messages, current_app

@main.route('/', methods=['GET', 'POST'])
def index_func():
    """
        It turns out that in a sessoin you can only stor a key/value pair and the value can not be another data structure.
        But, you might able to have a data structure as a value if the session in the server-side.
        session.get('posts', default='').split(',')
    """
    form = PostForm()
    if current_user.can_user(Permissions.WRITE) and form.validate_on_submit():
        post = Post.add_post(form, current_user._get_current_object())
        db.session.commit()
        # session['posts'] = form.body.data +  ',' + session.get('posts', default='')
        return redirect(url_for('.index_func'))
    return render_template('index.html', form=form, posts=Post.query.order_by(Post.timestamp.desc()).all()) #post=ssession.get('posts', default='').split(',')

@main.route('/user-profile/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user is None:
        abort(404)
    return render_template('user.html', posts=Post.query.order_by(Post.timestamp.desc()).all(), user=user) #post=ssession.get('posts', default='').split(',')

@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user._get_current_object())
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.username
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)

@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated.', 'success')
        return redirect(url_for('.user_profile', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.username
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)