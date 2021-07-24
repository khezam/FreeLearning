from . import main
from .. import db
from ..decorators import admin_required, permission_required
from .forms import PostForm, EditProfileForm, EditProfileAdminForm
from ..blueprint_models import User, Role, Permissions, Post
from flask_login import login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for, request, session, render_template, flash, get_flashed_messages, current_app, make_response

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
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
        if show_followed:
            query = current_user.followed_posts
        else:
            query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'], error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts, show_followed=show_followed, pagination=pagination) #post=ssession.get('posts', default='').split(',')

@main.route('/user-profile/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user is None:
        abort(404)
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'], error_out=False)
    posts = pagination.items
    return render_template('user.html', posts=posts, user=user, pagination=pagination) #post=ssession.get('posts', default='').split(',')

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
        return redirect(url_for('.user_profile', username=current_user.username))
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

@main.route('/post/<int:id>') 
def post(id):
    post = Post.query.get_or_404(id)
    return render_template('post.html', posts=[post])

@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can_user(Permissions.ADMIN):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('The post has been updated.', 'success')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)

@main.route('/follow/<username>')
@login_required
@permission_required(Permissions.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('.index_func'))
    if current_user.is_following(user):
        flash('You are already following this user.', 'warning')
        return redirect(url_for('.user_profile', username=username))
    current_user.follow_user(user)
    db.session.commit()
    flash(f'You are now following {username}.', 'success')
    return redirect(url_for('.user_profile', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permissions.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('.index_func'))
    if not current_user.is_following(user):
        flash('You are not following this user.', 'warning')
        return redirect(url_for('.user_profile', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'You are not following {username} anymore.', 'success')
    return redirect(url_for('.user_profile', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'], error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followers.html', user=user, title="Followers of", endpoint='.followers', pagination=pagination, follows=follows)


@main.route('/followed_by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('.index_func'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'], error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by", endpoint='.followed_by', pagination=pagination, follows=follows)

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index_func')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    response = make_response(redirect(url_for('.index_func')))
    response.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return response