import argon2
import os
from argon2.low_level import verify_secret
from flask.blueprints import Blueprint
from wtforms.validators import ValidationError
from app import app, db
from app.forms import LoginForm, RegistrationForm, KontaktForm, EditProfileForm, EmptyForm, PostForm
from flask import render_template, flash, redirect, url_for, session, request, current_app
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, chatroom, chatmessage, Post
from werkzeug.urls import url_parse, url_unparse
from datetime import datetime
from flask_babel import Babel
from flask_socketio import SocketIO
from argon2 import PasswordHasher, Type 
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2.exceptions import VerifyMismatchError
from app.forms import ResetPasswordForm
from app.email import *
from app.forms import ResetPasswordRequestForm



limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)  

ph = PasswordHasher(
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=16,
        salt_len=16,
        encoding='utf-8',
        type=Type.ID
    )
import sqlalchemy
from zxcvbn import zxcvbn

socketio = SocketIO(app)

@app.route('/chat/', methods=['GET', 'POST'])
@limiter.limit("100/minute", error_message='Error! Too many chats')
@login_required
def chatperson():
    chatroom = request.args.get("rid", None)
    if chatroom == None:
        chatroom = session['chatroom']
    session['chatroom'] = chatroom
    return render_template('chat.html', title="Chat System", user=current_user, chatroom=chatroom)

@app.route('/newchat/<username>', methods=['GET', 'POST'])
@login_required
def newchat(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('Du kan ikke chatte med deg selv!')
            return redirect(url_for('index'))
        current_user.chat(user)
        db.session.commit()
        return redirect(url_for('chatperson'))
    else:
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('Du kan ikke chatte med deg selv!')
            return redirect(url_for('index'))
        current_user.chat(user)
        db.session.commit()
        return redirect(url_for('chatperson'))

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)

@socketio.on('load messages')
def load_messages(json, methods=['GET', 'POST']):
    messages = chatmessage.query.filter(chatmessage.chat_id == session['chatroom']).limit(10)
    for message in messages:
        sender = message.username
        message = message.message
        socketio.emit('previous message', (sender, message))

@socketio.on('Load chats')
def load_messages(json, methods=['GET', 'POST']):
    chatrooms = chatroom.query.filter(chatroom.person1_id == current_user.id).limit(5)
    for chats in chatrooms:
        chats = chats.person2_id
        user = User.query.filter_by(id=chats).first()
        user = user.username
        socketio.emit('Load chatrooms', user)

@socketio.on('sent message')
def store_message(json, methods=['GET', 'POST']):
    message = str(json['message'])
    params = (str(session["chatroom"]), current_user.username, message)
    db.engine.execute('INSERT INTO chatmessage (chat_id, username, message) VALUES (?,?,?)', params)

@app.route('/edit_profile', methods=['GET', 'POST'])
@limiter.limit("10/minute", error_message='Error! Too many edits!')
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username, current_user.about_me)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Endringene din har blitt lagret.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    return render_template('index.html', title='Hjem')

#@app.route('/', methods=['GET'])
#def home():
 #   session['attempt']=5

@app.route('/leie', methods=['GET', 'POST'])
@limiter.limit("5/minute", error_message='Error! Too many posts')
@login_required
def leie():
    form = PostForm()
    if form.validate_on_submit():
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                post = Post(body=form.post.data, author=current_user, image=filename)
                db.session.add(post)
                db.session.commit()
                flash('Your post is now live!')
                return redirect(url_for('leie'))
    page = request.args.get('page', 1, type=int)
    posts = current_user.followed_posts().paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('leie', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('leie', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('leie.html', title='Home', form=form,
                           posts=posts.items, next_url=next_url,
                           prev_url=prev_url)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/hour", error_message='Error! Your username and password is not matching')
def login():
    #session.permanent = True
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None: 
    
            flash('Pålogging mislyktes. Ugyldig brukernavn eller passord.')

            return redirect(url_for('login'))
        try:
            user.check_password(form.password.data)
        except VerifyMismatchError:
            flash('Pålogging mislyktes. Ugyldig brukernavn eller passord.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=15)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Logg inn', form=form)

@app.route('/logout')
@limiter.limit("10/hour", error_message='Error!')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10/hour", error_message='Error! Can´t register another user')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # burde vi heller ha dette? 
       # hashed_password = ph.hash(form.password.data)
       # user = User(username=form.username.data, email=form.email.data, password=hashed_password) 
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data) # settes det "rene" passordet inn i databasen? Nei, henter metoden som hasher?
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/kontakt')
@limiter.limit("5/minute", error_message='Error! We don´t have the time to respond to that many questions')
def kontakt():
    form = KontaktForm()
    if form.validate_on_submit():
        flash('Login requested for user {}, remember_me={}'.format(
            form.username.data, form.remember_me.data))
        return redirect(url_for('index'))
    return render_template('kontakt.html', title='Kontakt oss', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    form = EmptyForm()
    return render_template('user.html', user=user, posts=posts.items,
                           next_url=next_url, prev_url=prev_url, form=form)

@app.route('/follow/<username>', methods=['POST'])
@limiter.limit("100/hour", error_message='Error! You are following too many people')
@login_required
def follow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot follow yourself!')
            return redirect(url_for('user', username=username))
        current_user.follow(user)
        db.session.commit()
        flash('You are following {}!'.format(username))
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))

@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot unfollow yourself!')
            return redirect(url_for('user', username=username))
        current_user.unfollow(user)
        db.session.commit()
        flash('You are not following {}.'.format(username))
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))


@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template("leie.html", title='Explore', posts=posts.items,
                            next_url=next_url, prev_url=prev_url)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)