from . import main
from .. import db
from ..decorators import admin_required, permission_required
from .forms import PostForm, EditProfileForm, EditProfileAdminForm, CommentForm
from ..blueprint_models import User, Role, Permissions, Post, Comment
from flask_login import login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for, request, session, render_template, flash, get_flashed_messages, current_app, make_response

"""
    This view function is for selenium testing to shutdown the server
"""
@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'

@main.route('/', methods=['GET', 'POST'])
@login_required
def index_func():
    """
        It turns out that in a sessoin you can only stor a key/value pair and the value can not be another data structure.
        But, you might able to have a data structure as a value if the session in the server-side.
        session.get('posts', default='').split(',')

        if the user has a permission to write and the form is validate, do the following:
            1- add the post to the session
            2- commit the changes to the database
            3- redirect the user endpoint named index_func and return.
        otherwise, 
            1- get the first page 
            2- declare a variable named show_followed and assign false to it.
            3- if the current user is logged in already:
                1- get the value of show_followed from the session
                2- if variable named show_followed evaluated to true, then do the following:
                    1- get the posts of the users that followed by the current user
                otherwise,
                    1- get the parent query

        @pagination variable: create a pagination and sort them by most recent posts
        @items: get the items from pagination
        return a response message that is a type of html.
    """
    form = PostForm()
    if current_user.can_user(Permissions.WRITE) and form.validate_on_submit():
        post = Post.add_post(form, current_user._get_current_object())
        db.session.commit()
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
    return render_template('index.html', form=form, posts=posts, show_followed=show_followed, pagination=pagination) 

"""
    @user_profile: This view function shows the user's profile with their posts
    1- fetch the user from the database and assign to the pointer variable named user 
    2- get the first page by from the uery string 
    3- create pagination
    4- get the items 
    5- return a response message that is a type of html.
"""
@main.route('/user-profile/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'], error_out=False)
    posts = pagination.items
    return render_template('user.html', posts=posts, user=user, pagination=pagination) 

"""
    @edit_profile: This view function edits the user's profile
    1- if the method of the request message is POST and the form is validated, then do the following:
        1- Access the name and assign it with current input of the user
        2- Access the location and assign it with current input of the user
        3- Access the about_me and assign it with current input of the user
        4- add the changes to the database session
        5- commit the changes
        6- flash the user 
        7- redirect the user the endpoint named user_profile registered to the bluprint named main
    otherwise,
        1- show the user's the current profile with the current values
        2- return back and html with the form
"""
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

"""
    @edit_profile_admin: This view function is almost the same as the view function right above
"""
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

"""
    @post: This view adds the user's comment to the Comment model
    1- if the method of the request message is POST and the form is validated, then do the following:
        1- create an instance of the class Comment and assign to the pointer variable named comment.
        Note: the _get_current_object() returns back the current user's object not the proxy object
        2- add the changes to the database session
        3- commit the changes to the database
    otherwise, 
        it is the same as the other view functions above
"""
@main.route('/post/<int:id>', methods=['GET', 'POST']) 
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been published.', 'success')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) // current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate( page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'], error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form, comments=comments, pagination=pagination)


"""
    @edit: This view function gives the user the ability to edit their posts.
"""
@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can_user(Permissions.ADMIN):
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

"""
    @follow: This view function lets users to follow other users
    1- fetch the user from the database and assign to the pointer variable named user
    2- if the variable named user evaluates to None meaning the user does not exist, then do the following:
        1- flash the damn user 
        2- redirect the damn user
    
    otherwise,
        if the current user is already following the other user, then do the following:
            1- let the user know that
            2- redirect them
        otherwise,
            1- let the current user follow the other user
            2- commit the changes to the database
            3- flash the user 
            4- redirect the user
"""
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

"""
    @unfollow: This view function lets users to unfollow other user.
    Note: its almost the same as the view function above
"""
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

@main.route('/moderate')
@login_required
@permission_required(Permissions.MODERATE)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'], error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments, pagination=pagination, page=page)

@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permissions.MODERATE)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))

@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permissions.MODERATE)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))