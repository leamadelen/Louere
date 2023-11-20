from datetime import datetime
from app import db
import sqlalchemy
from sqlalchemy import and_
from sqlalchemy.orm import backref
# tidligere hash-algoritme 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
from hashlib import md5
from flask import config, session
from time import time
import jwt
from app import app
# hash-algoritmen
from argon2 import PasswordHasher, Type 
ph = PasswordHasher(
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=16,
        salt_len=16,
        encoding='utf-8',
        type=Type.ID
    )


followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
    )

class chatmessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer)
    username = db.Column(db.String(64))
    message = db.Column(db.String(999))

class chatroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    person1_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    person2_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    chat_id = db.Column(db.Integer)

# Legger inn flere roller med ulik access # OWASP 1
class Role(object):
    roles = {}

    def __init__(self, name=None):
        # inisial til roller og tilgang
        self.name = name
        Role.roles[name] = self

    def get_name(self):
        #returnerer navnet til rollen
        return self.name

    def __repr__(self):
        return '<Role %s>' % self.name


class User(object):
    # rollen blir assigned til bruker

    def __init__(self, roles=[]):
        # inisialiserer rollen assigned til bruker når brukeren blir lagd eller oppdaterer senere
        self.roles = set(roles)

    def add_role(self, role):
        #adder rollen til denne brukeren
        self.roles.extend(role)

    def get_roles(self):
        # returnerer et generator objekt for rollen til brukeren
        for role in self.roles.copy():
            yield role

    def remove_role(self, role_name):
        # Fjerner en rolle gitt til brukeren
        # role_name: navnet til rollen som skal fjernes
        for role in self.get_roles():
            if role.get_name() == role_name:
                self.roles.remove(role)

    def __repr__(self):
        return '<User %s>' % self.roles
    


###
class User(db.Model, UserMixin,):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128)) # litt usikker på lengden, burde vær 16? 
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    chatroomperson1 = db.relationship('chatroom', foreign_keys='chatroom.person1_id', backref='chats', lazy='dynamic')
    chatroomperson2 = db.relationship('chatroom', foreign_keys='chatroom.person2_id', backref='chat', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        # hash passwords and return an encoded hash
        self.password_hash = ph.hash(password)
    
    def check_password(self, password):
        # verify that password matches hash
        return ph.verify(self.password_hash, password)
    
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)
            
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_ip = db.Column(db.String(100))
    active = db.Column(db.Boolean)
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0
    
    def followed_posts(self):
        followed = Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def chat(self, user):
        if not self.is_chatting(user):
            checkrow = sqlalchemy.text('SELECT COUNT(chat_id) FROM chatroom')
            amountrow = db.engine.execute(checkrow)
            amountrow = amountrow.fetchone()
            amountrow = amountrow[0]
            amountrow = amountrow/2 + 1
            sql = sqlalchemy.text('INSERT INTO chatroom (person1_id, person2_id, chat_id) VALUES ('+str(self.id)+', '+str(user.id)+', '+str(amountrow)+')')
            db.engine.execute(sql)
            sql = sqlalchemy.text('INSERT INTO chatroom (person1_id, person2_id, chat_id) VALUES ('+str(user.id)+', '+str(self.id)+', '+str(amountrow)+')')
            db.engine.execute(sql)
            session['chatroom'] = amountrow
        checkrow = chatroom.query.filter(and_(chatroom.person1_id == self.id, chatroom.person2_id == user.id)).limit(1)
        for row in checkrow:
            session['chatroom'] = row.chat_id


    def is_chatting(self, user):
        chatrooms = chatroom.query.filter_by(person1_id=self.id)
        return chatrooms.filter(
            chatroom.person2_id == user.id).count() > 0

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image = db.Column(db.String(999))

    def __repr__(self):
        return '<Post {}>'.format(self.body)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))